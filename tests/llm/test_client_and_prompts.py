"""
FirmGraph-LLM — Tests for LLM Prompts and Hybrid Client
"""
import pytest
from llm.prompts.templates import PromptTemplates
from llm.client import HybridLLMClient


class TestPromptTemplates:
    def test_start_prompt(self):
        pt = PromptTemplates()
        prompt = pt.start(
            source_func="recv",
            source_param=1,
            first_function_name="process_packet",
            first_function_code="int process_packet() { recv(sock, buf, 100); }",
            kg_evidence="Known socket input pattern",
        )
        assert "recv" in prompt
        assert "process_packet" in prompt
        assert "Known socket input pattern" in prompt

    def test_end_prompt_no_cwe_bias(self):
        pt = PromptTemplates()
        prompt = pt.end(
            sink_func="strcpy",
            sink_param=0,
            sink_function_name="copy_data",
            sink_function_code="strcpy(dest, src);",
            tainted_inputs="src",
            kg_evidence="",
        )
        assert "strcpy" in prompt
        assert "copy_data" in prompt
        # Verify schema doesn't hardcode CWE-78
        assert '"cwe": "CWE-78"' not in prompt


class TestHybridClient:
    def test_client_defaults(self):
        client = HybridLLMClient()
        assert client.model == "qwen2.5:1.5b"
        assert client._active_mode in ["local", "cloud"]


class TestReasoningAndRanking:
    def test_parse_verdict_with_surrounding_braces(self):
        from llm.reasoning.conversation import VulnerabilityAnalyzer
        noisy_output = """
        Analysis note: {debug_flag: 1}
        Verdict:
        ```json
        {
            "vulnerable": true,
            "cwe": "CWE-120",
            "confidence": 0.85,
            "explanation": "Buffer overflow detected"
        }
        ```
        Footer comment: {extra: 0}
        """
        parsed = VulnerabilityAnalyzer._parse_verdict(noisy_output)
        assert parsed["vulnerable"] is True
        assert parsed["cwe"] == "CWE-120"
        assert parsed["confidence"] == 0.85

    def test_ranker_strict_ordering(self):
        from llm.ranking.scorer import VulnerabilityRanker
        from llm.reasoning.conversation import VulnerabilityResult

        vr_safe = VulnerabilityResult(
            flow_id="f1", binary_name="b", vulnerable=False, cwe="None",
            confidence=0.0, explanation="", taint_trace="", patch_suggestion="",
        )
        vr_vuln = VulnerabilityResult(
            flow_id="f2", binary_name="b", vulnerable=True, cwe="CWE-78",
            confidence=0.1, explanation="", taint_trace="", patch_suggestion="",
        )
        ranker = VulnerabilityRanker()
        ranked = ranker.rank([vr_safe, vr_vuln])
        assert ranked[0].flow_id == "f2"  # Vulnerable must be first
        assert ranked[1].flow_id == "f1"  # Safe must be last
        assert ranked[0].final_score > ranked[1].final_score
        assert ranked[1].final_score < 0.0

    def test_function_record_source_param(self):
        from llm.reasoning.conversation import FunctionRecord
        fr = FunctionRecord(name="read_buf", pseudocode="", binary="test", is_source=True, source_param=2)
        assert fr.source_param == 2
