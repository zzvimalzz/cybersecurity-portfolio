"""Build the result JSON, check it, and write it safely.

Anything that depends on the clock sits under "timing". The digest covers everything
else, so two runs that see the same replies get the same digest."""
import hashlib
import json
import os
from datetime import timezone

from . import TOOL_NAME, __version__
from .classify import STATES, aggregate_states

RESULT_SCHEMA = "wqe7002-a1-tcp-syn-scan-result-v1"

NOTES = (
    "open = a SYN/ACK with the correct acknowledgement number was received; the scanner then sent RST.",
    "closed = an RST/ACK with the correct acknowledgement number was received.",
    "filtered-icmp-unreachable = a relevant ICMP destination-unreachable quoting our probe was received.",
    "filtered-or-no-response = no relevant reply within the timeout; this does not prove filtering, "
    "absence of a service, or that the host is down.",
    "Replies that match no sent probe are counted in summary.unmatched_packets and never change a state.",
)


def format_utc(moment):
    return moment.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def trial_dict(item):
    """One port in one trial, as it appears in the JSON."""
    return {
        "trial": item.trial,
        "state": item.state,
        "attempts_sent": item.attempts_sent,
        "syn_ack_received": item.syn_ack_received,
        "rst_received": item.rst_received,
        "rst_sent": item.rst_sent,
        "icmp_unreachable": [{"type": kind, "code": code, "source": who, "count": n}
                             for kind, code, who, n in item.icmp_unreachable],
        "duplicate_responses": item.duplicate_responses,
        "conflicting_evidence": item.conflicting_evidence,
    }


def build_result(scope, params, outcome, *, start_utc, end_utc, source_ip, scapy_version, argv):
    results, rtt, unstable, duplicates = [], {}, [], 0
    by_state = {state: [] for state in STATES}

    for index, port in enumerate(params.ports):
        trials = [outcome.trials[t][index] for t in range(params.trials)]
        state, stable = aggregate_states([item.state for item in trials])
        by_state[state].append(port)
        if not stable:
            unstable.append(port)
        duplicates += sum(item.duplicate_responses for item in trials)
        rtt[str(port)] = [item.rtt_ms for item in trials]
        results.append({
            "port": port,
            "protocol": "tcp",
            "state": state,
            "stable": stable,
            "trial_states": [item.state for item in trials],
            "trials": [trial_dict(item) for item in trials],
        })

    result = {
        "schema": RESULT_SCHEMA,
        "tool": {"name": TOOL_NAME, "version": __version__, "scapy_version": scapy_version},
        "option": "tcp-syn-scan",
        "scope": {"scope_id": scope.scope_id, "file_name": scope.file_name, "sha256": scope.sha256},
        "parameters": {
            "target": params.target,
            "ports": list(params.ports),
            "interface": params.interface,
            "source_ip": source_ip,
            "rate_pps": params.rate_pps,
            "attempts": params.attempts,
            "timeout_seconds": params.timeout_seconds,
            "trials": params.trials,
            "source_port_base": params.source_port_base,
            "probe": "TCP SYN, window 1024, MSS 1460, deterministic ISN per (port, trial, attempt)",
            "on_syn_ack": "send RST",
        },
        "invocation": {"argv": list(argv)},
        "results": results,
        "summary": {
            **by_state,
            "unstable_ports": unstable,
            "syn_probes_sent": outcome.syn_sent,
            "rst_sent": outcome.rst_sent,
            "duplicate_responses": duplicates,
            "unmatched_packets": outcome.unmatched_packets,
        },
        "notes": list(NOTES),
        "timing": {
            "start_utc": format_utc(start_utc),
            "end_utc": format_utc(end_utc),
            "duration_seconds": round(outcome.end_mono - outcome.start_mono, 3),
            "first_response_rtt_ms": rtt,
        },
    }
    result["deterministic_digest"] = compute_digest(result)
    return result


def dumps(result):
    """Sorted keys and fixed indent, so the same data always gives the same text."""
    return json.dumps(result, indent=2, sort_keys=True) + "\n"


def compute_digest(result):
    """SHA-256 of the result without its timing, invocation and digest fields."""
    stable = {k: v for k, v in result.items() if k not in ("timing", "invocation", "deterministic_digest")}
    return hashlib.sha256(dumps(stable).encode()).hexdigest()


def validate_result(result):
    """Raise ValueError if the result document is malformed."""
    def need(ok, what):
        if not ok:
            raise ValueError(f"invalid result: {what}")

    need(result.get("schema") == RESULT_SCHEMA, "schema")
    for key in ("tool", "option", "scope", "parameters", "results", "summary", "timing", "notes"):
        need(key in result, f"missing {key}")
    need(result["option"] == "tcp-syn-scan", "option")
    params = result["parameters"]
    for key in ("target", "ports", "rate_pps", "attempts", "timeout_seconds", "trials"):
        need(key in params, f"parameters.{key}")
    need("scope_id" in result["scope"] and "sha256" in result["scope"], "scope fields")
    need("start_utc" in result["timing"] and "end_utc" in result["timing"], "timing fields")
    need([r["port"] for r in result["results"]] == params["ports"], "results do not match parameters.ports")
    for entry in result["results"]:
        need(entry["state"] in STATES, f"state {entry['state']!r}")
        need(len(entry["trials"]) == params["trials"], "trial count")
        for trial in entry["trials"]:
            need(1 <= trial["attempts_sent"] <= params["attempts"], "attempts_sent bound")
    need(result["deterministic_digest"] == compute_digest(result), "digest mismatch")


def write_result(result, path, overwrite=False):
    """Write to a temp file first, then rename, so a crash never leaves half a file."""
    validate_result(result)
    if path.exists() and not overwrite:
        raise FileExistsError(f"{path} already exists (use --overwrite to replace it)")
    temp = path.with_name(path.name + ".tmp")
    try:
        temp.write_text(dumps(result), encoding="utf-8", newline="\n")
        os.replace(temp, path)
    except BaseException:
        temp.unlink(missing_ok=True)
        raise
