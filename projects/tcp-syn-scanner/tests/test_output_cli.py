"""Deterministic output, schema validation and CLI safety behaviour."""

import contextlib
import copy
import io
import json
import unittest
from datetime import datetime, timezone

import common  # noqa: F401
from common import TempDir, fake_session_factory, make_scope, run_scan, write_scope
from vscan.cli import main
from vscan.output import build_result, compute_digest, dumps, validate_result
from vscan.simnet import CLOSED, FILTERED, OPEN
from vscan.transport import TransportError

BEHAVIOUR = {22: OPEN, 80: OPEN, 443: CLOSED, 8080: FILTERED}


def result_for(start=datetime(2026, 11, 6, 1, 2, 3, tzinfo=timezone.utc), **kwargs):
    outcome, _, _, params = run_scan(BEHAVIOUR, **kwargs)
    return build_result(
        make_scope(), params, outcome,
        start_utc=start, end_utc=start, source_ip="172.28.70.2", scapy_version="test", argv=["vscan"],
    )


def call(argv, **kwargs):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = main(argv, **kwargs)
    return code, out.getvalue(), err.getvalue()


class OutputTests(unittest.TestCase):
    def test_identical_runs_serialise_identically_and_sort_keys(self):
        first, second = result_for(), result_for()
        self.assertEqual(dumps(first), dumps(second))
        text = dumps(first)
        self.assertEqual(json.loads(text), first)
        self.assertEqual(text, json.dumps(json.loads(text), indent=2, sort_keys=True) + "\n")

    def test_digest_ignores_wall_clock_but_not_observations(self):
        later = result_for(start=datetime(2030, 1, 1, tzinfo=timezone.utc))
        self.assertEqual(result_for()["deterministic_digest"], later["deterministic_digest"])
        self.assertNotEqual(dumps(result_for()), dumps(later))  # timing differs
        changed = copy.deepcopy(result_for())
        changed["results"][0]["state"] = "closed"
        self.assertNotEqual(compute_digest(changed), result_for()["deterministic_digest"])

    def test_result_records_scope_window_parameters_and_states(self):
        result = result_for()
        validate_result(result)
        self.assertEqual(result["scope"]["scope_id"], "wqe7002-a1-standard-tcp-syn-scan-v1")
        self.assertEqual(result["parameters"]["rate_pps"], 20.0)
        self.assertEqual(result["parameters"]["attempts"], 2)
        self.assertTrue(result["timing"]["start_utc"].endswith("Z"))
        states = {r["port"]: r["state"] for r in result["results"]}
        self.assertEqual(states, {22: "open", 80: "open", 443: "closed", 8080: "filtered-or-no-response"})
        self.assertEqual(result["summary"]["open"], [22, 80])
        # 22, 80, 443 answered on the first attempt; 8080 is silent and retried once.
        self.assertEqual((result["summary"]["syn_probes_sent"], result["summary"]["rst_sent"]), (5, 2))

    def test_validation_rejects_tampering(self):
        result = result_for()
        broken = copy.deepcopy(result)
        broken["results"][0]["state"] = "wide-open"
        with self.assertRaises(ValueError):
            validate_result(broken)
        broken = copy.deepcopy(result)
        broken["summary"]["open"] = []
        with self.assertRaises(ValueError):  # digest no longer matches
            validate_result(broken)
        broken = copy.deepcopy(result)
        del broken["timing"]
        with self.assertRaises(ValueError):
            validate_result(broken)


class CliTests(unittest.TestCase):
    def setUp(self):
        self._tmp = TempDir()
        self.dir = self._tmp.__enter__()
        self.scope = write_scope(self.dir)
        self.output = self.dir / "result.json"

    def tearDown(self):
        self._tmp.__exit__(None, None, None)

    def never_open(self, interface, target):
        raise AssertionError("plan mode must not open the network")

    def args(self, *extra):
        return ["--scope", str(self.scope), "--output", str(self.output), *extra]

    def test_plan_and_default_modes_transmit_nothing_and_write_nothing(self):
        for extra in ([], ["--plan"]):
            code, out, _ = call(self.args(*extra), session_factory=self.never_open)
            self.assertEqual(code, 0)
            self.assertIn("PLAN ONLY", out)
            self.assertIn("TCP SYN 172.28.70.10:443", out)
            self.assertFalse(self.output.exists())

    def test_plan_and_execute_are_mutually_exclusive(self):
        code, _, _ = call(self.args("--plan", "--execute"), session_factory=self.never_open)
        self.assertEqual(code, 2)

    def test_execute_writes_valid_deterministic_json(self):
        code, out, _ = call(self.args("--execute"), session_factory=fake_session_factory(BEHAVIOUR))
        self.assertEqual(code, 0)
        result = json.loads(self.output.read_text())
        validate_result(result)
        self.assertEqual(result["summary"]["closed"], [443])
        first_bytes = self.output.read_bytes()
        call(self.args("--execute", "--overwrite"), session_factory=fake_session_factory(BEHAVIOUR))
        second = json.loads(self.output.read_text())
        self.assertEqual(second["deterministic_digest"], result["deterministic_digest"])
        self.assertEqual(first_bytes.count(b"\r"), 0)

    def test_out_of_scope_requests_exit_nonzero_with_a_useful_message(self):
        for extra, fragment in [
            (["--target", "172.28.70.3"], "outside the scope"),
            (["--ports", "22,25"], "outside the scope"),
            (["--ports", "22,abc"], "invalid port"),
            (["--rate", "25"], "rate"),
            (["--attempts", "3"], "attempts"),
            (["--trials", "9"], "trials"),
        ]:
            with self.subTest(extra=extra):
                code, _, err = call(self.args("--execute", *extra), session_factory=self.never_open)
                self.assertEqual(code, 2)
                self.assertIn(fragment, err)
                self.assertFalse(self.output.exists())

    def test_invalid_scope_files_never_reach_the_network(self):
        bad = self.dir / "bad.json"
        bad.write_text(json.dumps({**json.loads(self.scope.read_text()), "target": "<TARGET>"}))
        code, _, err = call(["--scope", str(bad), "--output", str(self.output), "--execute"], session_factory=self.never_open)
        self.assertEqual(code, 2)
        self.assertIn("placeholder", err)
        code, _, err = call(["--scope", str(self.dir / "missing.json"), "--output", str(self.output), "--execute"], session_factory=self.never_open)
        self.assertEqual(code, 2)

    def test_existing_output_is_not_overwritten_without_the_flag(self):
        self.output.write_text("precious evidence")
        code, _, err = call(self.args("--execute"), session_factory=self.never_open)
        self.assertEqual(code, 2)
        self.assertEqual(self.output.read_text(), "precious evidence")

    def test_runtime_failure_is_nonzero_and_leaves_no_partial_output(self):
        def broken(interface, target):
            raise TransportError("cannot open raw send socket on 'eth0' (needs root/NET_RAW)")

        code, _, err = call(self.args("--execute"), session_factory=broken)
        self.assertEqual(code, 1)
        self.assertIn("NET_RAW", err)
        self.assertFalse(self.output.exists())

    def test_missing_output_directory_is_rejected_up_front(self):
        code, _, err = call(["--scope", str(self.scope), "--output", str(self.dir / "nope" / "r.json")], session_factory=self.never_open)
        self.assertEqual(code, 2)
        self.assertIn("output directory", err)


if __name__ == "__main__":
    unittest.main()
