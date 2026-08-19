"""
FirmGraph-LLM — Prompt Templates (LATTE Paper)
================================================
Implements ALL prompt templates from the LATTE paper (Liu et al., ACM TOSEM 2025):

  1. Sink identification prompt
  2. Source identification prompt
  3. Start prompt    — begin taint analysis conversation
  4. Middle prompt   — continue taint tracking per intermediate function
  5. End prompt      — final vulnerability verdict + CWE classification

Templates follow the LATTE paper's design:
  - Persona assignment ("expert program analyst")
  - Task specification (taint analysis, alias analysis, data dependency)
  - One-shot examples for sink/source classification
  - Structured JSON output formats
  - Step-by-step function-level reasoning
"""

import json
from dataclasses import dataclass

from llm.prompts.few_shot import SINK_EXAMPLES, SOURCE_EXAMPLES


# ── Output format schemas (for documentation and parsing) ─────────────────────

SINK_OUTPUT_SCHEMA = {
    "is_sink":           "bool  — True if this function is a taint sink",
    "vulnerable_params": "list[int] — 0-indexed parameter indices that are dangerous",
    "cwe_types":         "list[str] — associated CWE IDs e.g. ['CWE-78']",
    "reason":            "str  — one-sentence justification",
}

SOURCE_OUTPUT_SCHEMA = {
    "is_source":     "bool  — True if this function introduces external/tainted data",
    "output_params": "list[int] — 0-indexed params that receive tainted data (-1 = return value)",
    "reason":        "str  — one-sentence justification",
}

VERDICT_OUTPUT_SCHEMA = {
    "vulnerable":       "bool   — True if a real vulnerability exists in this flow",
    "cwe":              "str    — e.g. 'CWE-78' or 'None'",
    "confidence":       "float  — 0.0 to 1.0",
    "explanation":      "str    — why the vulnerability exists (or doesn't)",
    "taint_trace":      "str    — step-by-step trace of tainted data through the flow",
    "patch_suggestion": "str    — concrete fix recommendation",
}


@dataclass
class PromptTemplates:
    """
    All LATTE paper prompt templates as callable methods.
    Each method returns a fully formatted string ready to send to the LLM.
    """

    # ── Sink Identification ───────────────────────────────────────────────

    @staticmethod
    def sink_identification(func_name: str) -> str:
        """
        One-shot prompt: identify whether an external function is a taint sink.
        Uses SINK_EXAMPLES as the demonstration.
        """
        # Build one-shot demonstration from first two canonical examples
        demo = SINK_EXAMPLES[0]  # system()
        demo_input = demo["function"]
        demo_output = json.dumps({
            "is_sink":           demo["is_sink"],
            "vulnerable_params": demo["vulnerable_params"],
            "cwe_types":         demo["cwe_types"],
            "reason":            demo["reason"],
        }, indent=2)

        return f"""You are an expert binary security analyst specializing in taint analysis and vulnerability detection.

Your task: determine whether a given C library function is a **taint sink** — i.e., a function where attacker-controlled (tainted) data reaching it can cause a security vulnerability.

Output ONLY valid JSON matching this schema (no markdown, no explanation outside JSON):
{json.dumps(SINK_OUTPUT_SCHEMA, indent=2)}

--- EXAMPLE ---
Function: {demo_input}
Output:
{demo_output}
--- END EXAMPLE ---

Now classify the following function:
Function: {func_name}
Output:"""

    # ── Source Identification ─────────────────────────────────────────────

    @staticmethod
    def source_identification(func_name: str) -> str:
        """
        One-shot prompt: identify whether an external function is a taint source.
        Uses SOURCE_EXAMPLES as the demonstration.
        """
        demo = SOURCE_EXAMPLES[0]  # recv()
        demo_input = demo["function"]
        demo_output = json.dumps({
            "is_source":     demo["is_source"],
            "output_params": demo["output_params"],
            "reason":        demo["reason"],
        }, indent=2)

        return f"""You are an expert binary security analyst specializing in taint analysis.

Your task: determine whether a given C library function is a **taint source** — i.e., a function that receives data from an external, attacker-controllable input (network, stdin, environment, file, etc.) and stores it in an output parameter or return value.

Output ONLY valid JSON matching this schema (no markdown, no explanation outside JSON):
{json.dumps(SOURCE_OUTPUT_SCHEMA, indent=2)}

--- EXAMPLE ---
Function: {demo_input}
Output:
{demo_output}
--- END EXAMPLE ---

Now classify the following function:
Function: {func_name}
Output:"""

    # ── Start Prompt ──────────────────────────────────────────────────────

    @staticmethod
    def start(
        source_func: str,
        source_param: int,
        first_function_name: str,
        first_function_code: str,
        kg_evidence: str = "",
    ) -> str:
        """
        Start prompt: begin a multi-turn taint analysis conversation.

        Args:
            source_func:         Name of the taint source function (e.g. 'recv')
            source_param:        Parameter index that receives tainted data
            first_function_name: Name of the first function in the Dangerous Flow
            first_function_code: Decompiled pseudocode of the first function
            kg_evidence:         Optional KG evidence string (FirmGraph-LLM extension)
        """
        kg_section = ""
        if kg_evidence:
            kg_section = f"""
--- Knowledge Graph Evidence (from prior firmware analyses) ---
{kg_evidence}
Use this historical evidence to inform your analysis, but base your verdict on the code.
--- End Evidence ---
"""

        return f"""You are an expert program analyst specialized in binary vulnerability detection, taint analysis, and software security.

## Task
Perform a step-by-step taint analysis of a Dangerous Flow (DF) — a sequence of functions connecting a taint source to a potential vulnerability sink.

## Taint Source
- Function : {source_func}
- Parameter: param[{source_param}] receives attacker-controllable external data

## Analysis Instructions
For each function I provide:
1. Identify ALL variables that receive tainted data (directly or via alias/copy)
2. Track aliases: if tainted data is copied/assigned to another variable, mark that variable as tainted too
3. Note any sanitization: if tainted data passes through a validation or sanitization check, state this clearly
4. State which tainted variables are passed to the NEXT function (if any)
5. Be precise — reference specific variable names and line patterns from the code
{kg_section}
## First Function: `{first_function_name}`

```c
{first_function_code}
```

Analyze taint propagation through `{first_function_name}`. Which variables become tainted? Which are passed onward?"""

    # ── Middle Prompt ─────────────────────────────────────────────────────

    @staticmethod
    def middle(
        function_name: str,
        function_code: str,
        tainted_inputs: str,
        new_source_func: str = "",
        new_source_param: int = -1,
    ) -> str:
        """
        Middle prompt: continue taint analysis for an intermediate function.

        Args:
            function_name:   Name of this function
            function_code:   Decompiled pseudocode
            tainted_inputs:  Description of tainted variables entering this function
            new_source_func: If this function is also a taint source, its name
            new_source_param: Parameter index for the new source
        """
        new_source_section = ""
        if new_source_func:
            new_source_section = (
                f"\n**Note**: `{new_source_func}` is also called in this function "
                f"and introduces additional tainted data at param[{new_source_param}]. "
                "Include this in your taint tracking.\n"
            )

        return f"""Continue the taint analysis.

## Tainted Inputs Entering `{function_name}`
{tainted_inputs}
{new_source_section}
## Next Function: `{function_name}`

```c
{function_code}
```

Analyze how tainted data propagates through `{function_name}`. Which variables become tainted? Are there aliases or sanitization checks? Which tainted variables are passed to the next function?"""

    # ── End Prompt ────────────────────────────────────────────────────────

    @staticmethod
    def end(
        sink_func: str,
        sink_param: int,
        sink_function_name: str,
        sink_function_code: str,
        tainted_inputs: str,
        kg_evidence: str = "",
    ) -> str:
        """
        End prompt: final vulnerability verdict and CWE classification.

        Args:
            sink_func:          Name of the sink function (e.g. 'system', 'strcpy')
            sink_param:         Vulnerable parameter index of the sink
            sink_function_name: Name of the final function in the DF
            sink_function_code: Decompiled pseudocode of the final function
            tainted_inputs:     Tainted variables entering this function
            kg_evidence:        Optional KG evidence for grounded reasoning
        """
        kg_section = ""
        if kg_evidence:
            kg_section = f"""
--- Knowledge Graph Evidence ---
{kg_evidence}
If similar patterns were found vulnerable in prior analyses, cite them in your explanation.
--- End Evidence ---
"""

        return f"""You have completed the step-by-step taint analysis of this Dangerous Flow.

## Final Function: `{sink_function_name}` (contains sink: `{sink_func}`)

## Tainted Inputs Entering `{sink_function_name}`
{tainted_inputs}
{kg_section}
## Final Function Code

```c
{sink_function_code}
```

## Vulnerability Inspection

The potential sink is `{sink_func}()` at param[{sink_param}].

Based on your full taint analysis:
1. Does tainted data reach `{sink_func}` param[{sink_param}] WITHOUT adequate sanitization?
2. Does this constitute a real vulnerability?
3. What CWE type applies?

Supported CWEs: CWE-78 (OS Command Injection), CWE-120 (Buffer Overflow), CWE-134 (Format String), CWE-190 (Integer Overflow), CWE-606 (Unchecked Loop Condition)

Output ONLY valid JSON (no markdown fences, no extra text):
{json.dumps(VERDICT_OUTPUT_SCHEMA, indent=2)}"""


# Module-level singleton
TEMPLATES = PromptTemplates()
