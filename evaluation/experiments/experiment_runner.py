"""
evaluation.experiments.experiment_runner
========================================
Experiment Orchestration & Head-to-Head Evaluation.
Runs comparative evaluations between LATTE Baseline and FirmGraph-LLM.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Optional

from ..metrics.metrics_calculator import MetricsCalculator
from ..baselines.latte_baseline import LatteBaselineRunner
from analysis.analyzer import FirmGraphAnalyzer, AnalysisConfig
from llm.reasoning.conversation import DangerousFlow

log = logging.getLogger(__name__)


class ExperimentRunner:
    """Runs head-to-head comparison experiments between baseline and FirmGraph."""

    def __init__(self, results_dir: Path):
        self.results_dir = Path(results_dir)
        self.results_dir.mkdir(parents=True, exist_ok=True)
        self.calculator = MetricsCalculator()

    def run_comparison(
        self,
        flows: list[DangerousFlow],
        binary_name: str,
        baseline_runner: LatteBaselineRunner,
        firmgraph_analyzer: FirmGraphAnalyzer,
    ) -> dict:
        log.info(f"Running comparative experiment for {binary_name} ({len(flows)} flows)")

        base_results = baseline_runner.run(flows, binary_name)
        fg_results = firmgraph_analyzer.analyze(flows, binary_name)

        comparison = self.calculator.compare_systems(
            base_results, fg_results, ("LATTE_baseline", "FirmGraph_LLM")
        )

        def _is_vuln(item):
            if isinstance(item, dict):
                res = item.get("result")
                if res and hasattr(res, "vulnerable"):
                    return bool(res.vulnerable)
                return bool(item.get("vulnerable", False))
            res = getattr(item, "result", None)
            return bool(res.vulnerable if res else getattr(item, "vulnerable", False))

        result = {
            "experiment": binary_name,
            "flows_analyzed": len(flows),
            "comparison": comparison,
            "latte_vulnerable": sum(1 for r in base_results if _is_vuln(r)),
            "firmgraph_vulnerable": sum(1 for r in fg_results if _is_vuln(r)),
        }

        out_path = self.results_dir / f"{binary_name}_comparison.json"
        out_path.write_text(json.dumps(result, indent=2))
        log.info(f"Experiment saved → {out_path}")
        return result
