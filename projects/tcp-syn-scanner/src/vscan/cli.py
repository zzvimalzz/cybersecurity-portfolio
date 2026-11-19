"""Command line: read the flags, check them, then print the plan or run the scan."""
import argparse
import sys
from datetime import datetime, timezone
from pathlib import Path

from . import TOOL_NAME, __version__
from .engine import Scanner
from .output import build_result, write_result
from .packets import plan_probes
from .scope import DEFAULT_SOURCE_PORT_BASE, MAX_TRIALS, ScopeError, check, load_scope, resolve_parameters
from .transport import TransportError, open_scapy_session

EXIT_OK = 0
EXIT_RUNTIME = 1   # permissions, interface, capture or file-writing problem
EXIT_INVALID = 2   # bad scope file or a flag outside the scope


def build_parser():
    parser = argparse.ArgumentParser(
        prog=TOOL_NAME, description="Scope-enforced Scapy TCP SYN scanner. Without --execute nothing is sent.")
    add = parser.add_argument
    add("--version", action="version", version=f"{TOOL_NAME} {__version__}")
    add("--scope", required=True, metavar="SCOPE.json", help="the scope file (the authority)")
    add("--output", required=True, metavar="RESULT.json", help="where the result is written")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--plan", action="store_true", help="print the plan, send nothing (the default)")
    mode.add_argument("--execute", action="store_true", help="really send the probes")
    add("--overwrite", action="store_true", help="replace an existing output file")
    add("--target", help="must equal the scope's target")
    add("--ports", help="comma-separated; must all be in the scope's ports")
    add("--rate", type=float, help="packets per second (not above the scope's, max 20)")
    add("--attempts", type=int, help="tries per port (not above the scope's, max 2)")
    add("--timeout", type=float, help="seconds to wait after each round")
    add("--trials", type=int, default=1, help=f"extension: repeat the scan 1-{MAX_TRIALS} times")
    add("--source-port-base", type=int, default=DEFAULT_SOURCE_PORT_BASE, help="first source port used")
    return parser


def parse_ports(text):
    """'22,80' -> [22, 80]"""
    pieces = [piece.strip() for piece in text.split(",")]
    for piece in pieces:
        check(piece.isascii() and piece.isdigit(), f"invalid port in --ports: {piece!r}")
    return [int(piece) for piece in pieces]


def format_plan(scope, params, output):
    probes = plan_probes(scope.scope_id, params)
    lines = [
        f"PLAN ONLY - no packets will be transmitted ({TOOL_NAME} {__version__})",
        f"scope:       {scope.scope_id} (sha256 {scope.sha256[:16]}...)",
        f"target:      {params.target}",
        f"ports:       {', '.join(map(str, params.ports))}",
        f"interface:   {params.interface}",
        f"rate:        {params.rate_pps:g} packets/s (SYN and RST together)",
        f"attempts:    up to {params.attempts} per port per trial (2nd only if no reply to the 1st)",
        f"timeout:     {params.timeout_seconds:g} s after each round",
        f"trials:      {params.trials}",
        f"maximum SYN probes: {len(probes)}; one RST follows each valid SYN/ACK",
        f"output:      {output} (not written in plan mode)",
        "probes in send order (our source IP is read from the interface when executing):",
    ]
    for p in probes:
        lines.append(f"  trial {p.trial} attempt {p.attempt}: TCP SYN {params.target}:{p.port} "
                     f"sport={p.sport} seq={p.seq}")
    lines.append("run again with --execute to send.")
    return "\n".join(lines)


def fail(message, code):
    print(f"{TOOL_NAME}: error: {message}", file=sys.stderr)
    return code


def execute(scope, params, args, arguments, session_factory):
    """Send the probes and write the result file."""
    try:
        session = session_factory(params.interface, params.target)
    except Exception as error:
        return fail(f"cannot start the scan: {error}", EXIT_RUNTIME)
    try:
        start = datetime.now(timezone.utc)
        outcome = Scanner(scope.scope_id, params, session.transport, session.clock, session.source_ip).run()
        result = build_result(scope, params, outcome, start_utc=start, end_utc=datetime.now(timezone.utc),
                              source_ip=session.source_ip, scapy_version=session.scapy_version,
                              argv=[TOOL_NAME, *arguments])
        write_result(result, Path(args.output), overwrite=args.overwrite)
    except KeyboardInterrupt:
        return fail("interrupted; no result file written", 130)
    except (TransportError, OSError, ValueError) as error:
        return fail(f"scan or output failed: {error}", EXIT_RUNTIME)
    finally:
        session.close()

    summary = result["summary"]
    counts = ", ".join(f"{state}={len(summary[state])}" for state in
                       ("open", "closed", "filtered-icmp-unreachable", "filtered-or-no-response"))
    print(f"wrote {args.output}: {counts}; {summary['syn_probes_sent']} SYN, {summary['rst_sent']} RST")
    return EXIT_OK


def main(argv=None, *, session_factory=open_scapy_session):
    arguments = sys.argv[1:] if argv is None else list(argv)
    try:
        args = build_parser().parse_args(arguments)
    except SystemExit as stop:          # argparse already printed the message
        return int(stop.code or 0)

    output = Path(args.output)
    try:
        scope = load_scope(args.scope)
        params = resolve_parameters(
            scope, target=args.target, ports=parse_ports(args.ports) if args.ports is not None else None,
            rate_pps=args.rate, attempts=args.attempts, timeout_seconds=args.timeout,
            trials=args.trials, source_port_base=args.source_port_base)
        check(output.parent.is_dir(), f"output directory does not exist: {output.parent}")
        check(args.overwrite or not output.exists(), f"{output} already exists (use --overwrite to replace it)")
    except ScopeError as error:
        return fail(error, EXIT_INVALID)

    if not args.execute:                # the safe default: show the plan and stop
        print(format_plan(scope, params, output))
        return EXIT_OK
    return execute(scope, params, args, arguments, session_factory)
