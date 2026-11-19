#!/usr/bin/env python3
"""Repeatable evaluation of the repeated-trials extension on a SIMULATED lossy network.

This is a model, not a measurement of the course lab: it shows how the extension
behaves when probes or replies are lost, with seeded randomness so every run of
this script prints the same table. Real-lab trial comparisons come from
tools/run_experiment.sh with TRIALS=1 and TRIALS=5.

Usage: python tools/evaluate_extension.py [--runs 500] [--output evaluation.md]
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from vscan.classify import STATE_CLOSED, STATE_NONE, STATE_OPEN, aggregate_states  # noqa: E402
from vscan.engine import Scanner  # noqa: E402
from vscan.scope import parse_scope, resolve_parameters  # noqa: E402
from vscan.simnet import CLOSED, FILTERED, OPEN, SimClock, SimulatedNetwork  # noqa: E402

TARGET, SOURCE = "172.28.70.10", "172.28.70.2"
TRUTH = {22: OPEN, 80: OPEN, 443: CLOSED, 8080: FILTERED}
EXPECTED = {22: STATE_OPEN, 80: STATE_OPEN, 443: STATE_CLOSED, 8080: STATE_NONE}
SCOPE = {
    "schema": "wqe7002-recon-scope-v1", "scope_id": "evaluation", "option": "tcp-syn-scan",
    "environment": "isolated-course-lab", "interface": "eth0", "target": TARGET,
    "ports": sorted(TRUTH), "maximum_rate_pps": 20, "maximum_attempts": 2, "timeout_seconds": 1.5,
}
STRATEGIES = [
    ("A: 1 attempt, 1 trial", 1, 1),
    ("B: 2 attempts, 1 trial (baseline)", 2, 1),
    ("C: 2 attempts, 3 trials (extension)", 2, 3),
]


def run_once(attempts: int, trials: int, loss: float, seed: int):
    scope = parse_scope(SCOPE)
    params = resolve_parameters(scope, attempts=attempts, trials=trials)
    clock = SimClock()
    net = SimulatedNetwork(clock, TARGET, SOURCE, TRUTH, loss=loss, seed=seed)
    outcome = Scanner(scope.scope_id, params, net, clock, SOURCE).run()
    wrong = unstable = 0
    for index, port in enumerate(params.ports):
        state, stable = aggregate_states([outcome.trials[t][index].state for t in range(trials)])
        wrong += state != EXPECTED[port]
        unstable += not stable
    return wrong, unstable, outcome.syn_sent + outcome.rst_sent, clock.now


def evaluate(runs: int) -> str:
    lines = [
        f"Simulated lossy network, {runs} seeded runs per cell, ground truth: "
        "22 open, 80 open, 443 closed, 8080 silent. Loss applies independently to each probe and each reply.",
        "",
        "| Per-direction loss | Strategy | Port states wrong (of 4 per run) | Runs with a flagged-unstable port | Mean packets sent | Mean scan time (s) |",
        "|---|---|---|---|---|---|",
    ]
    for loss in (0.05, 0.20, 0.35):
        for label, attempts, trials in STRATEGIES:
            wrong = unstable_runs = packets = elapsed = 0.0
            for seed in range(runs):
                w, u, p, t = run_once(attempts, trials, loss, seed)
                wrong += w
                unstable_runs += u > 0
                packets += p
                elapsed += t
            lines.append(
                f"| {loss:.0%} | {label} | {wrong / runs:.3f} | {unstable_runs / runs:.1%} | "
                f"{packets / runs:.1f} | {elapsed / runs:.2f} |"
            )
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--runs", type=int, default=500)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    table = evaluate(args.runs)
    print(table)
    if args.output:
        args.output.write_text(table, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
