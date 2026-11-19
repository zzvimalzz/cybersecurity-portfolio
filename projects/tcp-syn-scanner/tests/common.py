"""Shared fixtures for the vscan tests."""

from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from vscan.engine import Scanner  # noqa: E402
from vscan.scope import parse_scope, resolve_parameters  # noqa: E402
from vscan.simnet import SimClock, SimulatedNetwork  # noqa: E402
from vscan.transport import Session  # noqa: E402

TARGET = "172.28.70.10"
SOURCE = "172.28.70.2"

SCOPE_DICT = {
    "schema": "wqe7002-recon-scope-v1",
    "scope_id": "wqe7002-a1-standard-tcp-syn-scan-v1",
    "option": "tcp-syn-scan",
    "environment": "isolated-course-lab",
    "interface": "eth0",
    "target": TARGET,
    "ports": [22, 80, 443, 8080],
    "maximum_rate_pps": 20,
    "maximum_attempts": 2,
    "timeout_seconds": 1.5,
    "capture_point": "workbench eth0; records the authorised scanner vantage point",
    "topology": "wqe7002-course-lab Compose internal bridge",
}


def scope_dict(**changes):
    data = dict(SCOPE_DICT)
    data.update(changes)
    return data


def make_scope(**changes):
    return parse_scope(scope_dict(**changes), "0" * 64, "scope.json")


def write_scope(directory: Path, **changes) -> Path:
    path = directory / "scope.json"
    path.write_text(json.dumps(scope_dict(**changes)), encoding="utf-8")
    return path


def run_scan(behaviour, *, trials=1, attempts=None, ports=None, net_kwargs=None, **param_overrides):
    """Run the real Scanner against the simulated network; return (outcome, net, clock, params)."""
    scope = make_scope()
    params = resolve_parameters(scope, trials=trials, attempts=attempts, ports=ports, **param_overrides)
    clock = SimClock()
    net = SimulatedNetwork(clock, TARGET, SOURCE, behaviour, **(net_kwargs or {}))
    outcome = Scanner(scope.scope_id, params, net, clock, SOURCE).run()
    return outcome, net, clock, params


def fake_session_factory(behaviour, **net_kwargs):
    def factory(interface, target):
        clock = SimClock()
        net = SimulatedNetwork(clock, target, SOURCE, behaviour, **net_kwargs)
        return Session(net, clock, SOURCE, "test-scapy")

    return factory


class TempDir:
    def __enter__(self) -> Path:
        self._tmp = tempfile.TemporaryDirectory()
        return Path(self._tmp.name)

    def __exit__(self, *exc) -> None:
        self._tmp.cleanup()
