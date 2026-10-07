"""
analysis.explainability.explainer
=================================
Vulnerability Explainability & Remediation Formatter.
Translates technical taint traces into human-readable explanations and patches.
"""

from __future__ import annotations

from typing import Optional
from llm.reasoning.conversation import VulnerabilityResult


class VulnerabilityExplainer:
    """Formats plain-English explanations and developer patches."""

    CWE_FRIENDLY_NAMES = {
        "CWE-78": "OS Command Injection",
        "CWE-120": "Buffer Overflow (Unbounded Memory Copy)",
        "CWE-134": "Uncontrolled Format String Vulnerability",
        "CWE-190": "Integer Overflow or Wraparound",
        "CWE-606": "Unchecked Loop Condition",
    }

    @classmethod
    def get_friendly_name(cls, cwe: str) -> str:
        return cls.CWE_FRIENDLY_NAMES.get(cwe, cwe)

    @staticmethod
    def format_triage_summary(result: VulnerabilityResult) -> str:
        status = "🔴 Vulnerable" if result.vulnerable else "🟢 Safe"
        return f"[{status}] {result.binary_name} — {result.cwe} (Confidence: {result.confidence:.2f})"
