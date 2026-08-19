"""
FirmGraph-LLM — Main Analysis Orchestrator + Report Generator
==============================================================
Ties the full pipeline together:
  DangerousFlow list → [GraphRAG] → LLM Analyzer → Ranker → Report
"""
import json
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from llm.reasoning.conversation import VulnerabilityAnalyzer, DangerousFlow, load_flows_from_json
from llm.ranking.scorer import VulnerabilityRanker, RankedVulnerability

log = logging.getLogger(__name__)


@dataclass
class AnalysisConfig:
    use_kg_retrieval: bool  = True   # False = LATTE baseline mode (B2)
    top_k_similar:    int   = 5
    save_results:     bool  = True
    results_dir:      Path  = Path("reports/")
    llm_weight:       float = 0.5
    kg_weight:        float = 0.3
    cwe_weight:       float = 0.2


class FirmGraphAnalyzer:
    """
    Main analysis orchestrator.
    Input : list[DangerousFlow] (produced by Ghidra RE — added later)
    Output: list[RankedVulnerability]
    """

    def __init__(self, llm_client,
                 graph_builder=None,
                 graphrag_retriever=None,
                 config: Optional[AnalysisConfig] = None):
        self.llm_client   = llm_client
        self.graph_builder = graph_builder
        self.retriever    = graphrag_retriever
        self.config       = config or AnalysisConfig()
        self.analyzer     = VulnerabilityAnalyzer(llm_client)
        self.ranker       = VulnerabilityRanker(
            llm_weight=self.config.llm_weight,
            kg_weight=self.config.kg_weight,
            cwe_weight=self.config.cwe_weight,
        )

    def analyze(self, flows: list[DangerousFlow], binary_name: str) -> list[RankedVulnerability]:
        """Full pipeline: retrieve → analyze → rank → ingest → report."""
        log.info(f"Analyzing {len(flows)} flows for binary '{binary_name}'")

        # Build KG evidence map if retrieval is enabled
        kg_evidence_map: dict[str, tuple[str, str]] = {}
        kg_scores:       dict[str, float]           = {}

        if self.config.use_kg_retrieval and self.retriever:
            for df in flows:
                try:
                    ctx = self.retriever.retrieve(
                        function_id=df.flow_id,
                        pseudocode=df.function_chain[-1].pseudocode if df.function_chain else "",
                        api_calls=[df.sink_func, df.source_func],
                        top_k=self.config.top_k_similar,
                    )
                    kg_evidence_map[df.flow_id] = (ctx.evidence_summary, ctx.evidence_summary)
                    kg_scores[df.flow_id]       = ctx.evidence_score
                    log.debug(f"  [{df.flow_id}] KG evidence score={ctx.evidence_score:.3f}")
                except Exception as e:
                    log.warning(f"  [{df.flow_id}] KG retrieval failed: {e}")

        # LLM analysis
        results = self.analyzer.analyze_batch(
            flows=flows,
            save_dir=self.config.results_dir / "raw" if self.config.save_results else None,
            kg_evidence_map=kg_evidence_map or None,
        )

        # Rank
        ranked = self.ranker.rank(results, kg_scores=kg_scores)

        # Ingest vulnerabilities into KG
        if self.graph_builder:
            from knowledge_graph.schema.nodes import BinaryNode
            bin_node = BinaryNode(id=binary_name, name=binary_name, firmware_id="unknown")
            for r in results:
                if r.vulnerable:
                    try:
                        self.graph_builder.ingest_vulnerability_result(r, bin_node)
                    except Exception as e:
                        log.warning(f"KG ingestion failed for {r.flow_id}: {e}")

        # Save report
        if self.config.save_results:
            self.save_report(ranked, binary_name)

        return ranked

    def analyze_from_json(self, flows_json_path: Path, binary_name: str) -> list[RankedVulnerability]:
        flows = load_flows_from_json(flows_json_path)
        return self.analyze(flows, binary_name)

    def save_report(self, ranked: list[RankedVulnerability], binary_name: str) -> Path:
        out_dir = Path(self.config.results_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
        report = self.ranker.to_report(ranked)
        report["binary_name"] = binary_name
        out_path = out_dir / f"{binary_name}_ranked.json"
        out_path.write_text(json.dumps(report, indent=2))
        log.info(f"Report saved → {out_path}")
        return out_path


# ── Report Generator ──────────────────────────────────────────────────────────

class ReportGenerator:
    """Generates structured JSON and Markdown vulnerability reports."""

    def generate_report(self, ranked: list[RankedVulnerability],
                        binary_name: str, config: AnalysisConfig) -> dict:
        mode = "firmgraph_llm" if config.use_kg_retrieval else "latte_baseline"
        vuln = [r for r in ranked if r.result.vulnerable]
        return {
            "binary":               binary_name,
            "analysis_mode":        mode,
            "total_flows_analyzed": len(ranked),
            "vulnerable_count":     len(vuln),
            "findings": [
                {
                    "rank":            r.rank,
                    "flow_id":         r.flow_id,
                    "function":        r.function_name,
                    "cwe":             r.cwe,
                    "confidence":      round(r.llm_confidence, 3),
                    "final_score":     round(r.final_score, 3),
                    "kg_evidence_used": r.result.kg_evidence_used,
                    "explanation":     r.result.explanation,
                    "taint_trace":     r.result.taint_trace,
                    "patch_suggestion": r.result.patch_suggestion,
                }
                for r in ranked
            ],
        }

    def save_json(self, report: dict, output_path: Path) -> None:
        Path(output_path).parent.mkdir(parents=True, exist_ok=True)
        Path(output_path).write_text(json.dumps(report, indent=2))
        log.info(f"JSON report → {output_path}")

    def save_markdown(self, report: dict, output_path: Path) -> None:
        Path(output_path).parent.mkdir(parents=True, exist_ok=True)
        lines = [
            f"# Vulnerability Report: `{report['binary']}`",
            f"**Mode:** {report['analysis_mode']}  ",
            f"**Flows Analyzed:** {report['total_flows_analyzed']}  ",
            f"**Vulnerable:** {report['vulnerable_count']}\n",
            "---\n## Findings\n",
        ]
        for f in report["findings"]:
            vuln_marker = "🔴" if f["confidence"] > 0 else "🟢"
            lines += [
                f"### {vuln_marker} Rank {f['rank']}: `{f['function']}` — {f['cwe']}",
                f"| Field | Value |",
                f"|-------|-------|",
                f"| Confidence | {f['confidence']:.3f} |",
                f"| Final Score | {f['final_score']:.3f} |",
                f"| KG Evidence | {'Yes' if f['kg_evidence_used'] else 'No'} |",
                f"\n**Explanation:** {f['explanation']}\n",
                f"**Taint Trace:** {f['taint_trace']}\n",
                f"**Patch:** {f['patch_suggestion']}\n",
                "---\n",
            ]
        Path(output_path).write_text("\n".join(lines))
        log.info(f"Markdown report → {output_path}")
