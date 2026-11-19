"""Invalid-scope and out-of-scope rejection."""

import unittest

import common  # noqa: F401  (sets up sys.path)
from common import TempDir, make_scope, scope_dict, write_scope
from vscan.scope import ScopeError, load_scope, parse_scope, resolve_parameters


class ScopeValidationTests(unittest.TestCase):
    def test_standard_scope_is_accepted(self):
        scope = make_scope()
        self.assertEqual(scope.target, "172.28.70.10")
        self.assertEqual(scope.ports, (22, 80, 443, 8080))

    def test_missing_key_is_rejected(self):
        data = scope_dict()
        del data["ports"]
        with self.assertRaisesRegex(ScopeError, "missing required keys: ports"):
            parse_scope(data)

    def test_placeholders_and_empty_values_are_rejected(self):
        for field, value in [
            ("scope_id", "<SCOPE_ID>"),
            ("scope_id", "TODO"),
            ("scope_id", "   "),
            ("interface", "{{iface}}"),
            ("capture_point", "REPLACE_ME"),
        ]:
            with self.subTest(field=field, value=value):
                with self.assertRaises(ScopeError):
                    parse_scope(scope_dict(**{field: value}))

    def test_bad_targets_are_rejected(self):
        for target in ["8.8.8.8", "127.0.0.1", "224.0.0.1", "0.0.0.0", "172.28.70.010", "example.com", 5, "172.28.70.0/28"]:
            with self.subTest(target=target):
                with self.assertRaises(ScopeError):
                    parse_scope(scope_dict(target=target))

    def test_bad_port_lists_are_rejected(self):
        bad = [[], [0], [65536], [22, 22], [22, "80"], [True], list(range(1, 32)), "22", [22.0]]
        for ports in bad:
            with self.subTest(ports=ports):
                with self.assertRaises(ScopeError):
                    parse_scope(scope_dict(ports=ports))

    def test_thirty_ports_is_the_maximum(self):
        self.assertEqual(len(make_scope(ports=list(range(1000, 1030))).ports), 30)

    def test_rate_attempt_and_timeout_bounds(self):
        for change in [
            {"maximum_rate_pps": 21},
            {"maximum_rate_pps": 0},
            {"maximum_rate_pps": float("inf")},
            {"maximum_attempts": 3},
            {"maximum_attempts": 0},
            {"maximum_attempts": True},
            {"timeout_seconds": 0},
            {"timeout_seconds": 60},
            {"option": "device-map"},
            {"environment": "production"},
            {"schema": "other-v9"},
        ]:
            with self.subTest(change=change):
                with self.assertRaises(ScopeError):
                    parse_scope(scope_dict(**change))

    def test_file_level_problems(self):
        with TempDir() as directory:
            missing = directory / "none.json"
            with self.assertRaisesRegex(ScopeError, "cannot read"):
                load_scope(missing)
            bad = directory / "bad.json"
            bad.write_text("{not json", encoding="utf-8")
            with self.assertRaisesRegex(ScopeError, "not valid JSON"):
                load_scope(bad)
            duplicate = directory / "dup.json"
            duplicate.write_text('{"ports": [22], "ports": [80]}', encoding="utf-8")
            with self.assertRaisesRegex(ScopeError, "duplicate key"):
                load_scope(duplicate)
            nan = directory / "nan.json"
            nan.write_text('{"maximum_rate_pps": NaN}', encoding="utf-8")
            with self.assertRaisesRegex(ScopeError, "non-finite"):
                load_scope(nan)
            array = directory / "array.json"
            array.write_text("[]", encoding="utf-8")
            with self.assertRaisesRegex(ScopeError, "JSON object"):
                load_scope(array)

    def test_load_records_hash_of_the_exact_file(self):
        import hashlib

        with TempDir() as directory:
            path = write_scope(directory)
            scope = load_scope(path)
            self.assertEqual(scope.sha256, hashlib.sha256(path.read_bytes()).hexdigest())


class ParameterNarrowingTests(unittest.TestCase):
    def test_defaults_use_the_manifest_limits(self):
        params = resolve_parameters(make_scope())
        self.assertEqual((params.rate_pps, params.attempts, params.timeout_seconds, params.trials), (20.0, 2, 1.5, 1))

    def test_out_of_scope_target_and_ports_are_rejected(self):
        scope = make_scope()
        with self.assertRaisesRegex(ScopeError, "outside the scope"):
            resolve_parameters(scope, target="172.28.70.3")
        with self.assertRaisesRegex(ScopeError, "outside the scope"):
            resolve_parameters(scope, ports=[22, 25])
        with self.assertRaises(ScopeError):
            resolve_parameters(scope, ports=[22, 22])
        with self.assertRaises(ScopeError):
            resolve_parameters(scope, ports=[])

    def test_cli_values_can_narrow_but_never_widen(self):
        scope = make_scope()
        params = resolve_parameters(scope, ports=[443, 22], rate_pps=5, attempts=1, timeout_seconds=0.5, trials=3)
        self.assertEqual((params.ports, params.rate_pps, params.attempts, params.trials), ((22, 443), 5.0, 1, 3))
        for kwargs in [{"rate_pps": 20.5}, {"rate_pps": 0}, {"attempts": 3}, {"attempts": 0}, {"trials": 6}, {"trials": 0}, {"timeout_seconds": 11}]:
            with self.subTest(kwargs=kwargs):
                with self.assertRaises(ScopeError):
                    resolve_parameters(scope, **kwargs)

    def test_a_lower_manifest_rate_cannot_be_exceeded(self):
        scope = make_scope(maximum_rate_pps=5)
        with self.assertRaises(ScopeError):
            resolve_parameters(scope, rate_pps=10)

    def test_source_port_range_must_fit(self):
        with self.assertRaises(ScopeError):
            resolve_parameters(make_scope(), source_port_base=65530)
        with self.assertRaises(ScopeError):
            resolve_parameters(make_scope(), source_port_base=80)


if __name__ == "__main__":
    unittest.main()
