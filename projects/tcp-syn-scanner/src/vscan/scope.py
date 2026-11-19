"""Scope file: load it, check it, and make sure every run stays inside it.

Two jobs:
  1. parse_scope / load_scope  - is the scope file itself valid?
  2. resolve_parameters        - may the command-line flags narrow it? (never widen)
Any problem raises ScopeError, so nothing is sent.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import math
import re
from dataclasses import dataclass
from pathlib import Path

MAX_PORTS = 30
MAX_RATE_PPS = 20 # maximum packets per second
MAX_ATTEMPTS = 2
MAX_TIMEOUT_SECONDS = 10
MAX_TRIALS = 5
DEFAULT_SOURCE_PORT_BASE = 40000

SCHEMA = "wqe7002-recon-scope-v1"
OPTION = "tcp-syn-scan"
ENVIRONMENT = "isolated-course-lab"

REQUIRED_KEYS = ("schema", "scope_id", "option", "environment", "interface",
                 "target", "ports", "maximum_rate_pps", "maximum_attempts", "timeout_seconds")

PLACEHOLDER = re.compile(
    r"^\s*$|<.*>|\{\{|\b(todo|tbd|changeme|fixme|replace_?me|xxx+)\b|\byour[_ -]", re.IGNORECASE)

class ScopeError(ValueError):
    """Raised when the scope or a flag is not allowed."""

@dataclass(frozen=True)
class Scope:
    """Allowed scope for the run"""
    scope_id: str
    interface: str
    target: str
    ports: tuple
    maximum_rate_pps: float
    maximum_attempts: int
    timeout_seconds: float
    sha256: str
    file_name: str

@dataclass(frozen=True)
class EffectiveParameters:
    """What this run will actually do (the scope, after any narrowing by flags)."""
    target: str
    ports: tuple
    interface: str
    rate_pps: float
    attempts: int
    timeout_seconds: float
    trials: int
    source_port_base: int

def check(condition, message):
    """Raise ScopeError(message) unless condition is true."""
    if not condition:
        raise ScopeError(message)

def is_whole(x):
    """A whole number. bool is excluded because Python treats True as 1."""
    return isinstance(x, int) and not isinstance(x, bool)

def is_number(x):
    """A normal finite number."""
    return isinstance(x, (int, float)) and not isinstance(x, bool) and math.isfinite(x)

def parse_scope(data, sha256="", file_name=""):
    """Check an already-decoded scope (a dict) and return a Scope."""
    check(isinstance(data, dict), "scope manifest must be a JSON object")
    missing = [key for key in REQUIRED_KEYS if key not in data]
    check(not missing, "scope manifest is missing required keys: " + ", ".join(missing))
    for key, value in data.items():
        check(not (isinstance(value, str) and PLACEHOLDER.search(value)),
              f"{key} is empty or a placeholder: {value!r}")

    check(data["schema"] == SCHEMA, f"unsupported scope schema {data['schema']!r}; expected {SCHEMA!r}")
    check(data["option"] == OPTION, f"scope option is {data['option']!r}; this tool only supports {OPTION!r}")
    check(data["environment"] == ENVIRONMENT, f"scope environment must be {ENVIRONMENT!r}")
    check(isinstance(data["scope_id"], str), "scope_id must be a string")
    check(isinstance(data["interface"], str) and re.fullmatch(r"[A-Za-z0-9_.:-]{1,15}", data["interface"]),
          f"interface is not a valid interface name: {data['interface']!r}")

    target = data["target"]
    check(isinstance(target, str), "target must be a string IPv4 address")
    try:
        ip = ipaddress.IPv4Address(target)
    except ValueError:
        raise ScopeError(f"target is not a valid IPv4 address: {target!r}") from None
    check(str(ip) == target, f"target must be written in canonical dotted-quad form: {target!r}")
    check(ip.is_private and not (ip.is_loopback or ip.is_link_local or ip.is_unspecified or ip.is_reserved),
          f"target {target} is not a private unicast lab address")

    ports = data["ports"]
    check(isinstance(ports, list) and 1 <= len(ports) <= MAX_PORTS,
          f"ports must be a list of 1 to {MAX_PORTS} TCP ports")
    check(all(is_whole(p) and 1 <= p <= 65535 for p in ports), "every port must be a whole number from 1 to 65535")
    check(len(set(ports)) == len(ports), "ports contains duplicates")

    rate, attempts, timeout = data["maximum_rate_pps"], data["maximum_attempts"], data["timeout_seconds"]
    check(is_number(rate) and 0 < rate <= MAX_RATE_PPS, f"maximum_rate_pps must be a number in (0, {MAX_RATE_PPS}]")
    check(is_whole(attempts) and 1 <= attempts <= MAX_ATTEMPTS, f"maximum_attempts must be a whole number in 1-{MAX_ATTEMPTS}")
    check(is_number(timeout) and 0 < timeout <= MAX_TIMEOUT_SECONDS, f"timeout_seconds must be a number in (0, {MAX_TIMEOUT_SECONDS}]")

    return Scope(data["scope_id"], data["interface"], target, tuple(sorted(ports)),
                 float(rate), attempts, float(timeout), sha256, file_name)

def _no_duplicate_keys(pairs):
    """json hook: plain json silently keeps the last of two identical keys; we refuse."""
    keys = [key for key, _ in pairs]
    check(len(keys) == len(set(keys)), "duplicate key in scope manifest")
    return dict(pairs)

def _no_nan(name):
    """json hook: refuse NaN / Infinity."""
    raise ScopeError(f"non-finite number in scope manifest: {name}")


def load_scope(path):
    """Read the scope file from disk, check it, and return a Scope."""
    path = Path(path)
    try:
        raw = path.read_bytes()
        data = json.loads(raw.decode("utf-8"), object_pairs_hook=_no_duplicate_keys, parse_constant=_no_nan)
    except OSError as error:
        raise ScopeError(f"cannot read scope manifest {path}: {error.strerror}") from None
    except ValueError as error:
        if isinstance(error, ScopeError):
            raise
        raise ScopeError(f"scope manifest {path} is not valid JSON: {error}") from None
    return parse_scope(data, hashlib.sha256(raw).hexdigest(), path.name)


def resolve_parameters(scope, *, target=None, ports=None, rate_pps=None, attempts=None,
                       timeout_seconds=None, trials=1, source_port_base=DEFAULT_SOURCE_PORT_BASE):
    """Combine the scope with optional flags; return EffectiveParameters or raise ScopeError."""
    check(target is None or target == scope.target,
          f"target {target} is outside the scope manifest (authorised: {scope.target})")

    ports = scope.ports if ports is None else ports
    check(len(ports) > 0 and len(set(ports)) == len(ports), "requested ports must be non-empty with no duplicates")
    outside = sorted(set(ports) - set(scope.ports))
    check(not outside, "port(s) outside the scope manifest: " + ", ".join(map(str, outside)))

    max_rate = min(scope.maximum_rate_pps, MAX_RATE_PPS)
    rate = max_rate if rate_pps is None else rate_pps
    check(is_number(rate) and 0 < rate <= max_rate, f"rate must be in (0, {max_rate:g}] packets per second")

    max_attempts = min(scope.maximum_attempts, MAX_ATTEMPTS)
    attempts = max_attempts if attempts is None else attempts
    check(is_whole(attempts) and 1 <= attempts <= max_attempts, f"attempts must be a whole number in 1-{max_attempts}")

    timeout = scope.timeout_seconds if timeout_seconds is None else timeout_seconds
    check(is_number(timeout) and 0 < timeout <= MAX_TIMEOUT_SECONDS, f"timeout must be in (0, {MAX_TIMEOUT_SECONDS}] seconds")

    check(is_whole(trials) and 1 <= trials <= MAX_TRIALS, f"trials must be a whole number in 1-{MAX_TRIALS}")

    probes = trials * len(ports) * attempts
    check(is_whole(source_port_base) and source_port_base >= 1024 and source_port_base + probes - 1 <= 65535,
          f"source port base must be >= 1024 and leave {probes} unique ports below 65536")

    return EffectiveParameters(scope.target, tuple(sorted(ports)), scope.interface,
                               float(rate), attempts, float(timeout), trials, source_port_base)
