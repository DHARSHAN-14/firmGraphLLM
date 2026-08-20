"""
FirmGraph-LLM — Evaluation Module
====================================
Metrics, LATTE baseline (B2), and experiment runner.
"""
import json
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from llm.reasoning.conversation import load_flows_from_json
from analysis.analyzer import FirmGraphAnalyzer, AnalysisConfig, ReportGenerator

log = logging.getLogger(__name__)


# ── Metrics ───────────────────────────────────────────────────────────────────

@dataclass
class EvaluationMetrics:
    true_positives:  int
    false_positives: int
    true_negatives:  int
    false_negatives: int
    precision:  float
    recall:     float
    f1_score:   float
    accuracy:   float
    top_k_recall: dict  # {k: recall_at_k}
    mrr:        float   # Mean Reciprocal Rank

    def to_dict(self) -> dict:
        return {
            "TP": self.true_positives,  "FP": self.false_positives,
            "TN": self.true_negatives,  "FN": self.false_negatives,
            "precision": round(self.precision, 4),
            "recall":    round(self.recall, 4),
            "f1_score":  round(self.f1_score, 4),
            "accuracy":  round(self.accuracy, 4),
            "top_k_recall": {str(k): round(v, 4) for k, v in self.top_k_recall.items()},
            "mrr":       round(self.mrr, 4),
        }

    def __str__(self) -> str:
        return (f"P={self.precision:.3f} R={self.recall:.3f} "
                f"F1={self.f1_score:.3f} Acc={self.accuracy:.3f} MRR={self.mrr:.3f}")


class MetricsCalculator:
    """
    Computes evaluation metrics against the Juliet ground truth.
    Ground truth JSON: data/juliet/ground_truth.json
    """

    def __init__(self, ground_truth_path: Path):
        self.gt_path = Path(ground_truth_path)
        self._gt: dict[str, dict] = {}  # filename → entry

        if self.gt_path.exists():
            data = json.loads(self.gt_path.read_text())
            for entry in data.get("entries", []):
                self._gt[entry["filename"]] = entry
            log.info(f"Loaded {len(self._gt)} ground truth entries from {self.gt_path}")
        else:
            log.warning(f"Ground truth not found at {self.gt_path}")

    def evaluate(self, ranked_results: list, binary_names: list[str]) -> EvaluationMetrics:
        """
        Compare ranked results against ground truth.
        Each result's binary_name is matched against ground truth entries.

        TP: result.vulnerable=True  AND ground truth has this binary as vulnerable
        FP: result.vulnerable=True  AND ground truth says not vulnerable
        TN: result.vulnerable=False AND ground truth says not vulnerable
        FN: result.vulnerable=False AND ground truth says vulnerable
        """
        tp = fp = tn = fn = 0
        reciprocal_ranks = []

        for i, r in enumerate(ranked_results):
            # Match by binary name against ground truth
            binary = getattr(r, "binary_name", None) or r.get("binary_name", "")
            actual_vuln = self._is_actually_vulnerable(binary)
            predicted   = getattr(r, "result", None)
            pred_vuln   = predicted.vulnerable if predicted else r.get("vulnerable", False)

            if pred_vuln and actual_vuln:
                tp += 1
                reciprocal_ranks.append(1.0 / (i + 1))
            elif pred_vuln and not actual_vuln:
                fp += 1
            elif not pred_vuln and not actual_vuln:
                tn += 1
            else:
                fn += 1

        total = tp + fp + tn + fn
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall    = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1        = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0
        accuracy  = (tp + tn) / total if total > 0 else 0.0
        mrr       = sum(reciprocal_ranks) / len(reciprocal_ranks) if reciprocal_ranks else 0.0

        # Top-K recall
        top_k_recall = {}
        all_vuln = [r for r in ranked_results
                    if self._is_actually_vulnerable(
                        getattr(r, "binary_name", r.get("binary_name", "")))]
        for k in [1, 3, 5, 10]:
            top_k = ranked_results[:k]
            hits  = sum(1 for r in top_k
                        if self._is_actually_vulnerable(
                            getattr(r, "binary_name", r.get("binary_name", ""))))
            top_k_recall[k] = hits / len(all_vuln) if all_vuln else 0.0

        return EvaluationMetrics(tp, fp, tn, fn, precision, recall, f1, accuracy, top_k_recall, mrr)

    def evaluate_cwe_accuracy(self, results: list) -> dict[str, float]:
        """Accuracy of CWE classification per CWE type."""
        from collections import defaultdict
        correct   = defaultdict(int)
        total     = defaultdict(int)

        for r in results:
            # Support both dataclass (RankedVulnerability) and dict results
            if isinstance(r, dict):
                binary   = r.get("binary_name", "")
                pred_cwe = r.get("cwe", "Unknown")
            else:
                binary   = getattr(r, "binary_name", "")
                pred_cwe = getattr(r, "cwe", "Unknown")

            gt       = self._gt.get(binary, {})
            true_cwe = f"CWE-{gt.get('cwe_id', '')}"
            if not pred_cwe:
                continue
            total[true_cwe] += 1
            if pred_cwe == true_cwe:
                correct[true_cwe] += 1

        return {cwe: correct[cwe] / total[cwe] for cwe in total if total[cwe] > 0}

    def compare_systems(self, a_results: list, b_results: list,
                        names: tuple[str, str]) -> dict:
        """Side-by-side metric comparison of two systems."""
        a_m = self.evaluate(a_results, [])
        b_m = self.evaluate(b_results, [])
        return {
            names[0]: a_m.to_dict(),
            names[1]: b_m.to_dict(),
            "delta": {
                "precision": round(b_m.precision - a_m.precision, 4),
                "recall":    round(b_m.recall    - a_m.recall,    4),
                "f1_score":  round(b_m.f1_score  - a_m.f1_score,  4),
                "mrr":       round(b_m.mrr        - a_m.mrr,       4),
            },
        }

    def _is_actually_vulnerable(self, binary_name: str) -> bool:
        """
        Look up whether a binary is actually vulnerable in ground truth.
        Juliet 'bad' binaries contain vulnerable code; 'good' binaries are patched.
        Uses exact key match first, then path-component-safe matching.
        """
        # 1. Exact match
        if binary_name in self._gt:
            return self._gt[binary_name].get("is_vulnerable", True)

        # 2. Match by full path component (not substring) to avoid false positives
        binary_stem = Path(binary_name).stem if "." in binary_name else binary_name
        for fname, entry in self._gt.items():
            parts = Path(fname).parts
            if binary_stem in parts or Path(fname).stem == binary_stem:
                return entry.get("is_vulnerable", True)

        # 3. Juliet naming fallback: 'bad' path → vulnerable, 'good' path → safe
        name_lower = binary_name.lower()
        if "/bad/" in name_lower or name_lower.endswith("_bad"):
            return True
        if "/good/" in name_lower or name_lower.endswith("_good"):
            return False

        return False  # not in GT → treat as non-vulnerable


# ── LATTE Baseline (B2) ───────────────────────────────────────────────────────

class LATTEBaseline:
    """
    Runs the LATTE-equivalent baseline (B2):
    LLM + prompt sequences, NO KG retrieval.
    Isolates the contribution of the Knowledge Graph.
    """

    def __init__(self, llm_client):
        config        = AnalysisConfig(use_kg_retrieval=False, save_results=True,
                                       results_dir=Path("reports/latte_baseline/"))
        self.analyzer = FirmGraphAnalyzer(llm_client=llm_client, config=config)

    def run(self, flows: list, binary_name: str) -> list:
        log.info(f"[LATTE Baseline] Analyzing {len(flows)} flows for '{binary_name}'")
        return self.analyzer.analyze(flows, binary_name)

    def run_from_json(self, flows_json_path: Path, binary_name: str) -> list:
        flows = load_flows_from_json(flows_json_path)
        return self.run(flows, binary_name)


# ── Experiment Runner ─────────────────────────────────────────────────────────

class ExperimentRunner:
    """
    Runs the full comparative experiment:
    B2 (LATTE baseline) vs P (FirmGraph-LLM) on the same flows.
    """

    def __init__(self, ground_truth_path: Path, results_dir: Path):
        self.gt_path    = Path(ground_truth_path)
        self.results_dir = Path(results_dir)
        self.results_dir.mkdir(parents=True, exist_ok=True)
        self.report_gen = ReportGenerator()

    def run_experiment(self, flows: list, binary_name: str,
                       latte: LATTEBaseline,
                       firmgraph: FirmGraphAnalyzer,
                       metrics: MetricsCalculator) -> dict:
        """
        1. Run LATTE baseline
        2. Run FirmGraph-LLM
        3. Compute metrics for both
        4. Return comparison dict
        """
        log.info(f"=== Experiment: {binary_name} ===")

        log.info("[1/2] Running LATTE baseline...")
        base_results = latte.run(flows, binary_name)

        log.info("[2/2] Running FirmGraph-LLM...")
        fg_results   = firmgraph.analyze(flows, binary_name)

        comparison   = metrics.compare_systems(base_results, fg_results,
                                               ("LATTE_baseline", "FirmGraph_LLM"))
        result = {
            "experiment":      binary_name,
            "flows_analyzed":  len(flows),
            "comparison":      comparison,
            "latte_vulnerable":    sum(1 for r in base_results if getattr(r, "result", None) and r.result.vulnerable),
            "firmgraph_vulnerable": sum(1 for r in fg_results if getattr(r, "result", None) and r.result.vulnerable),
        }
        log.info(f"Results: LATTE={comparison['LATTE_baseline']['f1_score']:.3f} F1 | "
                 f"FirmGraph={comparison['FirmGraph_LLM']['f1_score']:.3f} F1")
        return result

    def save_experiment_results(self, results: dict, experiment_name: str) -> Path:
        out = self.results_dir / f"{experiment_name}.json"
        out.write_text(json.dumps(results, indent=2))
        log.info(f"Experiment saved → {out}")
        return out
