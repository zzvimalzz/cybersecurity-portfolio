---
layout: project
title: Tiny Honeypot
permalink: /projects/tiny-honeypot/
order: 4
summary: A loopback-only decoy that logs who probes it.
tools: [Python 3, asyncio, Nmap 7.99, curl, Kali Linux]
skills: [python, network-scanning, linux]
download: honeypot.py
shot: |
  nmap -sV   2222  ssh   OpenSSH 8.9p1
             8081  http  Apache 2.4.41
  log        21 events, 8 login attempts
shot_highlight: "8 login attempts"
figures:
  - { src: evidence/screenshots/start.png, w: 842, h: 405, wide: true, tone: black, alt: "Two terminal panes: the honeypot reports it is listening on 127.0.0.1 for fake SSH on 2222 and a fake web login on 8081, and ss shows both ports bound to 127.0.0.1." }
  - { src: evidence/screenshots/nmap.png, w: 948, h: 938, tone: black, alt: "Nmap version scan of ports 2222 and 8081 reporting OpenSSH 8.9p1 and Apache 2.4.41, then a scan of the WSL address showing both ports filtered, with the honeypot logging each probe above." }
  - { src: evidence/screenshots/probes.png, w: 938, h: 852, tone: black, alt: "curl fetching the login page, eight login posts that each return 401, a request for /admin that returns 404 and a netcat connection that receives the fake SSH banner, with the matching log events above." }
  - { src: evidence/screenshots/log.png, w: 1095, h: 348, wide: true, tone: black, alt: "The log holds 21 lines. The first events show the Nmap probes, and the login lines record the user name, the secret length of 6 and a short hash." }
  - { src: evidence/screenshots/summary.png, w: 1095, h: 198, wide: true, tone: black, alt: "The summary reports 21 events from one source, flags a scan across both services as T1595 and 8 login attempts as T1110, and lists the usernames, paths and user agents." }
  - { src: evidence/screenshots/login-page.png, w: 1520, h: 250, wide: true, alt: "The fake staff login page served at 127.0.0.1:8081, with a Staff portal heading, User and Pass fields and a Sign in button." }
---

## Objective

Build a small decoy that looks like an SSH server and a staff login page, record every probe against it, and check that my own Nmap scan and a scripted login attempt show up in the log. [Download honeypot.py](honeypot.py) and run `python3 honeypot.py run`. It needs only Python 3.8 or later.

**Authorisation:** the decoy listens on `127.0.0.1` only, and I probed it only from the same machine. The fake services hold no real data and the script offers no option to bind another address.

## Environment and tools

| Item | Detail |
| --- | --- |
| Language | Python 3.14.7, standard library only (`asyncio`) |
| Decoys | Fake SSH on port 2222 (banner only) and a fake login page on port 8081 |
| Probe tools | Nmap 7.99, curl, netcat |
| Platform | Kali Linux on WSL 2, Windows 11 host |
| Environment record | [environment](evidence/00-environment.txt) |

## Method

1. **Start the decoys.** `python3 honeypot.py run` opens both ports and appends one JSON line per connection. I confirmed with `ss -tln` that both ports are bound to `127.0.0.1`: [start](evidence/01-start.txt).
2. **Scan them.** `nmap -sV -p 2222,8081 127.0.0.1` from the same machine, then `nmap -Pn -p 2222,8081` against the instance's WSL address: [scans](evidence/02-nmap.txt).
3. **Probe them.** One `curl` request for the login page, eight `curl` login posts with different user names, a request for `/admin`, and a netcat connection to the SSH port: [probes](evidence/03-probes.txt).
4. **Read the log.** Every connection became one JSON line with time, source, path and user agent: [log](evidence/04-honeypot-log.txt).
5. **Summarise.** `python3 honeypot.py summary` groups events by source and applies two rules, one for a source that touched both services (ATT&CK T1595) and one for five or more login attempts (T1110): [summary](evidence/05-summary.txt).

## Results

| Finding | Evidence | Risk | Fix |
| --- | --- | --- | --- |
| Both decoys listen on `127.0.0.1` only. On the WSL address both ports show as filtered. | [start](evidence/01-start.txt), [scans](evidence/02-nmap.txt) | Low. Nothing is reachable from another host. | Keep the bind fixed. Test again after any change to the listener. |
| Nmap version detection reported OpenSSH 8.9p1 and Apache 2.4.41, which are the banners the script sends. | [scans](evidence/02-nmap.txt) | Informational. A banner alone makes a decoy look real to a scanner. | Add a real key exchange so a client that goes further is also fooled and logged. |
| The log holds 21 events from one source. The summary flagged a scan across both services and 8 login attempts. | [log](evidence/04-honeypot-log.txt), [summary](evidence/05-summary.txt) | Informational. The detection rules work on my own traffic. | Add a time window so a slow attack is not missed. |
| Login attempts record the user name, the length of the secret and the first 8 characters of its SHA-256, never the secret itself. | [log](evidence/04-honeypot-log.txt) | Low. Even the short hash lets me spot a reused guess without storing it. | Drop the hash if reuse tracking is not needed. |

Nmap treats the decoy as a real server, and its own probe paths appear in the log, so a defender sees what the scanner tried. The summary also shows the limit of the approach: every event came from `127.0.0.1`, so the source-based rules say little until the decoy sits on a network with other machines.

The screenshots come from a second run of the same commands on 2026-11-22, which again produced 21 events and 8 login attempts. The text evidence above is from the first run on 2026-11-19. The log and summary screenshots read the log from that second run, and the login-page image is a render of the live page without a browser frame.

<!-- figures -->

## What I would do differently

- Run the decoy on a host-only network with a second lab machine, so the source addresses differ and the rules mean something.
- Replace the banner with a real SSH emulation such as Cowrie, which records the commands an attacker types after a login.
- Rotate the log file, add a rate limit per source, and cap how many connections the decoy accepts.
- Feed the log to Wazuh, so the decoy produces alerts rather than a file.
