"""
FirmGraph-LLM — Tests for Evaluation & Metrics Module
"""
import pytest
from pathlib import Path
from evaluation.evaluation import EvaluationMetrics, MetricsCalculator


class TestEvaluationMetrics:
    def test_metrics_calculation(self):
        m = EvaluationMetrics(
            true_positives=4,
            false_positives=1,
            true_negatives=4,
            false_negatives=1,
            precision=0.8,
            recall=0.8,
            f1_score=0.8,
            accuracy=0.8,
            top_k_recall={"1": 0.5, "3": 1.0},
            mrr=0.75,
        )
        d = m.to_dict()
        assert d["TP"] == 4
        assert d["FP"] == 1
        assert d["precision"] == 0.8
        assert d["f1_score"] == 0.8
        assert "P=0.800" in str(m)


class TestMetricsCalculator:
    def test_evaluate_synthetic(self, tmp_path):
        gt_file = tmp_path / "ground_truth.json"
        gt_file.write_text('{"entries": [{"filename": "vuln_bin", "is_vulnerable": true, "cwe_id": 78}, {"filename": "safe_bin", "is_vulnerable": false, "cwe_id": 78}]}')

        calc = MetricsCalculator(gt_file)
        assert len(calc._gt) == 2

        results = [
            {"binary_name": "vuln_bin", "vulnerable": True, "cwe": "CWE-78"},
            {"binary_name": "safe_bin", "vulnerable": False, "cwe": "CWE-78"},
        ]
        metrics = calc.evaluate(results, ["vuln_bin", "safe_bin"])
        assert metrics.true_positives == 1
        assert metrics.true_negatives == 1
        assert metrics.false_positives == 0
        assert metrics.false_negatives == 0
        assert metrics.precision == 1.0
        assert metrics.recall == 1.0
        assert metrics.accuracy == 1.0
