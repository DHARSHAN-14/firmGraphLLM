"""
FirmGraph-LLM — Multi-Turn Vulnerability Analyzer (LATTE Core)
================================================================
Implements the LATTE paper's Prompt Sequence (PS) conversation:

  Start Prompt  → LLM analyzes first function in the Dangerous Flow
  Middle Prompt → LLM continues per intermediate function
  End Prompt    → LLM delivers vulnerability verdict + CWE classification

This is the central reasoning engine of the system.
"""

import json
import logging
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from llm.prompts.templates import TEMPLATES

log = logging.getLogger(__name__)


# ── Data structures ────────────────────────────────────────────────────────────

@dataclass
class FunctionRecord:
    """A single function's metadata and decompiled pseudocode."""
    name:       str
    pseudocode: str
    binary:     str
    address:    str  = ""
    is_source:  bool = False
    is_sink:    bool = False
    source_param: int = 0   # param index that receives tainted data when is_source=True
    api_calls:  list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "name":       self.name,
            "binary":     self.binary,
            "address":    self.address,
            "is_source":  self.is_source,
            "is_sink":    self.is_sink,
            "api_calls":  self.api_calls,
            "pseudocode": self.pseudocode[:500] + "..." if len(self.pseudocode) > 500 else self.pseudocode,
        }


@dataclass
class DangerousFlow:
    """
    A Dangerous Flow (DF) — a function call chain connecting a taint
    source to a taint sink, as extracted by static analysis.
    """
    flow_id:         str
    binary_name:     str
    source_func:     str          # e.g. 'recv'
    source_param:    int          # param index that receives tainted data
    sink_func:       str          # e.g. 'system'
    sink_param:      int          # vulnerable param index
    function_chain:  list[FunctionRecord]  # ordered: source→...→sink
    expected_cwe:    str = ""     # ground truth CWE (for evaluation)

    def __post_init__(self):
        if len(self.function_chain) < 1:
            raise ValueError(f"DangerousFlow {self.flow_id} must have at least 1 function")

    @classmethod
    def from_dict(cls, d: dict) -> "DangerousFlow":
        """Deserialize from a JSON dict (e.g. loaded from file)."""
        chain = [FunctionRecord(**f) for f in d.get("function_chain", [])]
        return cls(
            flow_id=d["flow_id"],
            binary_name=d["binary_name"],
            source_func=d["source_func"],
            source_param=d.get("source_param", 0),
            sink_func=d["sink_func"],
            sink_param=d.get("sink_param", 0),
            function_chain=chain,
            expected_cwe=d.get("expected_cwe", ""),
        )

    def to_dict(self) -> dict:
        return {
            "flow_id":        self.flow_id,
            "binary_name":    self.binary_name,
            "source_func":    self.source_func,
            "source_param":   self.source_param,
            "sink_func":      self.sink_func,
            "sink_param":     self.sink_param,
            "expected_cwe":   self.expected_cwe,
            "function_chain": [f.to_dict() for f in self.function_chain],
        }


@dataclass
class VulnerabilityResult:
    """Full output of a single Dangerous Flow analysis."""
    flow_id:          str
    binary_name:      str
    vulnerable:       bool
    cwe:              str
    confidence:       float
    explanation:      str
    taint_trace:      str
    patch_suggestion: str
    raw_conversation: list[dict]  = field(default_factory=list)
    analysis_time_sec: float      = 0.0
    kg_evidence_used: bool        = False

    def to_dict(self) -> dict:
        return {
            "flow_id":           self.flow_id,
            "binary_name":       self.binary_name,
            "vulnerable":        self.vulnerable,
            "cwe":               self.cwe,
            "confidence":        round(self.confidence, 4),
            "explanation":       self.explanation,
            "taint_trace":       self.taint_trace,
            "patch_suggestion":  self.patch_suggestion,
            "analysis_time_sec": round(self.analysis_time_sec, 2),
            "kg_evidence_used":  self.kg_evidence_used,
        }


# ── Vulnerability Analyzer ─────────────────────────────────────────────────────

class VulnerabilityAnalyzer:
    """
    Multi-turn LLM conversation for taint flow analysis following the LATTE paper.

    Conversation structure (per Dangerous Flow):
      1. Start prompt  — persona + source context + first function
      2. Middle prompt — one per intermediate function (may be 0 middle turns)
      3. End prompt    — final verdict request with sink context

    The conversation history is maintained in `messages` list and passed to
    the LLM as a proper multi-turn chat session.
    """

    def __init__(self, client):
        """
        Args:
            client: OllamaClient instance
        """
        self.client = client

    # ── Main entry point ───────────────────────────────────────────────────

    def analyze_flow(
        self,
        df: DangerousFlow,
        start_kg_evidence: str = "",
        end_kg_evidence:   str = "",
    ) -> VulnerabilityResult:
        """
        Run the full LATTE Prompt Sequence for one Dangerous Flow.

        Args:
            df:                DangerousFlow to analyze
            start_kg_evidence: KG evidence string injected into Start prompt
            end_kg_evidence:   KG evidence string injected into End prompt

        Returns:
            VulnerabilityResult with the LLM's verdict.
        """
        t0 = time.time()
        chain = df.function_chain
        messages: list[dict] = []

        # ── Step 1: Start Prompt ───────────────────────────────────────────
        first_func = chain[0]
        start_prompt = TEMPLATES.start(
            source_func=df.source_func,
            source_param=df.source_param,
            first_function_name=first_func.name,
            first_function_code=first_func.pseudocode,
            kg_evidence=start_kg_evidence,
        )
        messages.append({"role": "user", "content": start_prompt})
        start_response = self.client.chat(messages)
        messages.append({"role": "assistant", "content": start_response})
        log.debug(f"[{df.flow_id}] Start response: {start_response[:200]}...")

        # Keep track of what's tainted as we go
        current_taint_summary = self._summarize_taint(start_response, first_func.name)

        # ── Step 2: Middle Prompts (one per intermediate function) ─────────
        for i, func in enumerate(chain[1:-1], start=1):
            # Detect if this intermediate function is also a source
            new_src_func  = func.name if func.is_source else ""
            new_src_param = func.source_param if func.is_source else -1

            middle_prompt = TEMPLATES.middle(
                function_name=func.name,
                function_code=func.pseudocode,
                tainted_inputs=current_taint_summary,
                new_source_func=new_src_func,
                new_source_param=new_src_param,
            )
            messages.append({"role": "user", "content": middle_prompt})
            mid_response = self.client.chat(messages)
            messages.append({"role": "assistant", "content": mid_response})
            log.debug(f"[{df.flow_id}] Middle[{i}] response: {mid_response[:200]}...")
            current_taint_summary = self._summarize_taint(mid_response, func.name)

        # ── Step 3: End Prompt ─────────────────────────────────────────────
        last_func = chain[-1]
        end_prompt = TEMPLATES.end(
            sink_func=df.sink_func,
            sink_param=df.sink_param,
            sink_function_name=last_func.name,
            sink_function_code=last_func.pseudocode,
            tainted_inputs=current_taint_summary,
            kg_evidence=end_kg_evidence,
        )
        messages.append({"role": "user", "content": end_prompt})
        end_response = self.client.chat(messages)
        messages.append({"role": "assistant", "content": end_response})
        log.debug(f"[{df.flow_id}] End response: {end_response[:300]}...")

        # ── Parse verdict ──────────────────────────────────────────────────
        verdict = self._parse_verdict(end_response)
        elapsed = time.time() - t0

        vulnerable_val = verdict.get("vulnerable", False)
        if isinstance(vulnerable_val, str):
            vulnerable = "true" in vulnerable_val.lower() and "false" not in vulnerable_val.lower()
        else:
            vulnerable = bool(vulnerable_val)

        confidence_val = verdict.get("confidence", 0.5)
        try:
            confidence = float(confidence_val)
        except (ValueError, TypeError):
            confidence = 0.9 if vulnerable else 0.1

        result = VulnerabilityResult(
            flow_id=df.flow_id,
            binary_name=df.binary_name,
            vulnerable=vulnerable,
            cwe=str(verdict.get("cwe", "Unknown")),
            confidence=confidence,
            explanation=str(verdict.get("explanation", end_response)),
            taint_trace=str(verdict.get("taint_trace", "")),
            patch_suggestion=str(verdict.get("patch_suggestion", "")),
            raw_conversation=messages,
            analysis_time_sec=elapsed,
            kg_evidence_used=bool(start_kg_evidence or end_kg_evidence),
        )

        log.info(
            f"[{df.flow_id}] → vulnerable={result.vulnerable} cwe={result.cwe} "
            f"confidence={result.confidence:.2f} time={elapsed:.1f}s"
        )
        return result

    # ── Batch analysis ─────────────────────────────────────────────────────

    def analyze_batch(
        self,
        flows: list[DangerousFlow],
        save_dir: Optional[Path] = None,
        kg_evidence_map: Optional[dict[str, tuple[str, str]]] = None,
    ) -> list[VulnerabilityResult]:
        """
        Analyze multiple Dangerous Flows sequentially.

        Args:
            flows:            List of DangerousFlow objects
            save_dir:         If provided, save each result as JSON here
            kg_evidence_map:  Optional dict flow_id → (start_evidence, end_evidence)

        Returns:
            List of VulnerabilityResult objects.
        """
        results = []
        if save_dir:
            save_dir = Path(save_dir)
            save_dir.mkdir(parents=True, exist_ok=True)

        for i, df in enumerate(flows):
            log.info(f"Analyzing flow {i+1}/{len(flows)}: {df.flow_id}")
            start_ev = end_ev = ""
            if kg_evidence_map and df.flow_id in kg_evidence_map:
                start_ev, end_ev = kg_evidence_map[df.flow_id]

            try:
                result = self.analyze_flow(df, start_ev, end_ev)
            except Exception as e:
                log.error(f"Flow {df.flow_id} analysis failed: {e}")
                result = VulnerabilityResult(
                    flow_id=df.flow_id,
                    binary_name=df.binary_name,
                    vulnerable=False,
                    cwe="Error",
                    confidence=0.0,
                    explanation=f"Analysis error: {e}",
                    taint_trace="",
                    patch_suggestion="",
                )

            results.append(result)

            if save_dir:
                out_file = save_dir / f"{df.flow_id}.json"
                out_file.write_text(json.dumps(result.to_dict(), indent=2))
                log.debug(f"Saved result → {out_file}")

        vuln_count = sum(1 for r in results if r.vulnerable)
        log.info(f"Batch done: {len(flows)} flows, {vuln_count} vulnerable")
        return results

    # ── Internal helpers ───────────────────────────────────────────────────

    @staticmethod
    def _summarize_taint(llm_response: str, func_name: str) -> str:
        """
        Extract a concise taint summary from the LLM's intermediate response
        to pass as `tainted_inputs` to the next prompt.
        """
        # Take the concluding paragraph without prematurely truncating variable names
        paragraphs = [p.strip() for p in llm_response.split("\n\n") if p.strip()]
        if paragraphs:
            summary = paragraphs[-1] if len(paragraphs[-1]) <= 1000 else paragraphs[-1][:1000] + "..."
        else:
            summary = llm_response.strip()[:1000]
        return f"From `{func_name}`: {summary}"


    @staticmethod
    def _parse_verdict(text: str) -> dict:
        """
        Robustly parse the JSON verdict from the LLM's End prompt response.
        Handles markdown code fences and leading/trailing text.
        """
        # Strip markdown fences
        text = re.sub(r"```(?:json)?\s*", "", text)
        text = re.sub(r"```", "", text).strip()

        # Try direct parse
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            pass

        # Try finding JSON block between outer braces
        start_idx = text.find("{")
        end_idx = text.rfind("}")
        if start_idx != -1 and end_idx != -1 and end_idx > start_idx:
            candidate = text[start_idx : end_idx + 1]
            try:
                return json.loads(candidate)
            except json.JSONDecodeError:
                pass

        # Try smaller non-greedy JSON blocks
        for m in re.finditer(r"\{.*?\}", text, re.DOTALL):
            try:
                return json.loads(m.group())
            except json.JSONDecodeError:
                continue

        # Fallback: heuristic parsing from natural language
        log.warning("Could not parse JSON verdict; using heuristic fallback.")
        lower = text.lower()
        vulnerable = any(k in lower for k in ["vulnerable", "vulnerability exists", "is vulnerable"])
        cwe = "Unknown"
        for cwe_id in ["CWE-78", "CWE-120", "CWE-134", "CWE-190", "CWE-606"]:
            if cwe_id.lower() in lower:
                cwe = cwe_id
                break
        return {
            "vulnerable":       vulnerable,
            "cwe":              cwe,
            "confidence":       0.5,
            "explanation":      text[:1000],
            "taint_trace":      "",
            "patch_suggestion": "",
        }


# ── Utility: load flows from JSON ──────────────────────────────────────────────

def load_flows_from_json(path: Path) -> list[DangerousFlow]:
    """
    Load a list of DangerousFlow objects from a JSON file.
    Expected format: list of dicts matching DangerousFlow.from_dict()
    """
    data = json.loads(Path(path).read_text())
    if isinstance(data, dict):
        data = [data]
    flows = []
    for d in data:
        try:
            flows.append(DangerousFlow.from_dict(d))
        except Exception as e:
            log.warning(f"Skipping invalid flow entry: {e}")
    log.info(f"Loaded {len(flows)} DangerousFlows from {path}")
    return flows
