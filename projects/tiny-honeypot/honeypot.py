#!/usr/bin/env python3
import argparse
import asyncio
import hashlib
import json
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import parse_qs

BIND = "127.0.0.1"
BANNER = b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n"
PAGE = b"""<!doctype html><html><head><title>Staff portal</title></head><body>
<h1>Staff portal</h1><form method="post" action="/login">
<label>User <input name="u"></label> <label>Pass <input name="p" type="password"></label>
<button>Sign in</button></form></body></html>"""
BURST = 5


def now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def record(log, event):
    event = {"ts": now(), **event}
    with open(log, "a", encoding="utf-8") as handle:
        handle.write(json.dumps(event) + "\n")
    print(json.dumps(event), flush=True)


async def ssh_client(reader, writer, log):
    src = writer.get_extra_info("peername")[0]
    writer.write(BANNER)
    await writer.drain()
    try:
        data = await asyncio.wait_for(reader.read(256), timeout=3)
    except asyncio.TimeoutError:
        data = b""
    record(log, {"service": "ssh", "src": src, "client": data.decode("latin-1").strip()[:80]})
    writer.close()


async def web_client(reader, writer, log):
    src = writer.get_extra_info("peername")[0]
    try:
        head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=3)
    except (asyncio.TimeoutError, asyncio.IncompleteReadError, asyncio.LimitOverrunError):
        record(log, {"service": "web", "src": src, "method": "", "path": "", "agent": ""})
        writer.close()
        return
    lines = head.decode("latin-1").split("\r\n")
    parts = lines[0].split(" ")
    method, path = (parts + ["", ""])[:2]
    headers = {k.lower(): v for k, _, v in (l.partition(": ") for l in lines[1:] if ": " in l)}
    event = {"service": "web", "src": src, "method": method, "path": path[:120], "agent": headers.get("user-agent", "")[:80]}

    status, body = "404 Not Found", b"Not found"
    if method == "GET" and path == "/":
        status, body = "200 OK", PAGE
    elif method == "POST" and path == "/login":
        size = min(int(headers.get("content-length", "0") or 0), 1024)
        raw = await asyncio.wait_for(reader.readexactly(size), timeout=3) if size else b""
        fields = parse_qs(raw.decode("latin-1"))
        secret = fields.get("p", [""])[0]
        event.update({"user": fields.get("u", [""])[0][:40], "secret_len": len(secret), "secret_hash": hashlib.sha256(secret.encode()).hexdigest()[:8]})
        status, body = "401 Unauthorized", b"Invalid login"
    record(log, event)

    writer.write(f"HTTP/1.1 {status}\r\nServer: Apache/2.4.41 (Ubuntu)\r\nContent-Type: text/html\r\nContent-Length: {len(body)}\r\nConnection: close\r\n\r\n".encode() + body)
    await writer.drain()
    writer.close()


async def serve(args):
    ssh = await asyncio.start_server(lambda r, w: ssh_client(r, w, args.log), BIND, args.ssh_port)
    web = await asyncio.start_server(lambda r, w: web_client(r, w, args.log), BIND, args.web_port)
    print(f"Listening on {BIND}: fake SSH on {args.ssh_port}, fake web login on {args.web_port}. Logging to {args.log}", flush=True)
    async with ssh, web:
        try:
            await asyncio.wait_for(asyncio.gather(ssh.serve_forever(), web.serve_forever()), timeout=args.seconds or None)
        except asyncio.TimeoutError:
            pass


def summary(args):
    log = Path(args.log)
    if not log.exists():
        sys.exit(f"No log at {log}")
    events = [json.loads(line) for line in log.read_text(encoding="utf-8").splitlines() if line.strip()]
    by_src = defaultdict(list)
    for event in events:
        by_src[event["src"]].append(event)
    print(f"{len(events)} events from {len(by_src)} source address(es)\n")
    for src, items in by_src.items():
        services = Counter(e["service"] for e in items)
        logins = [e for e in items if e.get("user") is not None]
        print(f"{src}: " + ", ".join(f"{n} {s}" for s, n in services.items()))
        if len(services) > 1:
            print("  touched both services    MITRE ATT&CK T1595 active scanning")
        if len(logins) >= BURST:
            users = Counter(e["user"] for e in logins).most_common(3)
            print(f"  {len(logins)} login attempts    MITRE ATT&CK T1110 brute force")
            print("  usernames tried: " + ", ".join(f"{u or '(empty)'} x{n}" for u, n in users))
        paths = Counter(e["path"] for e in items if e["service"] == "web" and e["path"])
        if paths:
            print("  paths requested: " + ", ".join(f"{p} x{n}" for p, n in paths.most_common(4)))
        agents = {e["agent"] for e in items if e.get("agent")}
        if agents:
            print("  user agents: " + "; ".join(sorted(agents))[:160])


def main():
    parser = argparse.ArgumentParser(description="A tiny honeypot that listens on the loopback interface only.")
    sub = parser.add_subparsers(dest="cmd", required=True)
    run = sub.add_parser("run", help="start the fake services")
    run.add_argument("--ssh-port", type=int, default=2222)
    run.add_argument("--web-port", type=int, default=8081)
    run.add_argument("--log", default="honeypot.jsonl")
    run.add_argument("--seconds", type=int, default=0, help="stop after this many seconds")
    show = sub.add_parser("summary", help="summarise a log")
    show.add_argument("--log", default="honeypot.jsonl")
    args = parser.parse_args()
    if args.cmd == "run":
        try:
            asyncio.run(serve(args))
        except KeyboardInterrupt:
            pass
    else:
        summary(args)


if __name__ == "__main__":
    main()
