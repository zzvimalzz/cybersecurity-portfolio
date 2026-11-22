---
layout: project
title: TCP SYN scanner
permalink: /projects/tcp-syn-scanner/
order: 1
summary: A scope-enforced Scapy port scanner checked against Nmap.
tools: [Python 3, Scapy 2.7.0, Nmap 7.94, Docker, tcpdump]
skills: [python, network-scanning, virtualisation]
shot: |
  vscan   22 open     80 open
          443 open    8080 open
  nmap    4 of 4 agree
  tests   52 passing
shot_highlight: "4 of 4 agree"
figures:
  - { src: evidence/screenshots/lab-run.png, w: 1760, h: 976, wide: true, alt: "Terminal output of the lab experiment: the Scapy scan finds four open ports, and Nmap lists 22, 80, 443 and 8080 as open with a SYN/ACK reason." }
  - { src: evidence/screenshots/packet-list.png, w: 1760, h: 868, alt: "Packet list of the capture: an ARP lookup, then a SYN, a SYN/ACK and two RST packets for each of ports 22, 80, 443 and 8080." }
  - { src: evidence/screenshots/dry-run.png, w: 1760, h: 796, alt: "Dry run that prints the scope, the target 172.28.70.10, the four ports, 20 packets per second and the planned probes, with nothing transmitted." }
  - { src: evidence/screenshots/unit-tests.png, w: 1760, h: 328, wide: true, alt: "Unit test run that reports 52 tests and OK." }
---

## Objective

Build a TCP SYN port scanner that refuses to scan anything outside a written scope, then check its answers against Nmap on the same target. The scanner is `vscan`, written for WQE7002 Advanced Network Security Programming (Assignment 1, option B).

**Authorisation:** every real scan ran inside the isolated course lab the lecturer supplied, against one host in the private range (`172.28.70.10`), with the ports and rate limits set in the lecturer-issued scope file. The scanner refuses targets that are not private, more than 30 ports, more than 20 packets per second and more than 2 attempts.

## Environment and tools

| Item | Detail |
| --- | --- |
| Scanner | `vscan` 1.0.0, Python 3.10 or later, Scapy 2.7.0 builds the packets |
| Comparison tool | Nmap 7.94, used only after the scan. The scanner never calls it. |
| Lab | The course lab (Docker Compose, internal bridge). It is not included here because it belongs to the course and was used unchanged. |
| Capture | `tcpdump` in the lab container, covering the Scapy run only |
| Tests | 52 unit tests with a simulated network. Re-run on 19/11/2026 on Kali Linux (WSL 2) with Python 3.14.7: 52 passing. |
| Assistance | I drafted the design and had Claude Code draft the source, tests and run script. I read and changed the code, ran the tests, ran the lab experiment, and did the extension evaluation. |

## Method

1. **Write the scope.** The scanner loads a JSON scope and rejects malformed files, duplicate keys, placeholders and out-of-range values before doing anything: [scope.json](evidence/scope.json).
2. **Run the tests.** `PYTHONPATH=src python3 -m unittest discover -s tests` runs 52 tests with no network traffic: [unit tests](evidence/unit-tests.txt).
3. **Dry run.** `python3 -m vscan --scope evidence/scope.json --output /tmp/result.json` prints the plan, including every probe and its sequence number, and transmits nothing: [dry run](evidence/dry-run.txt).
4. **Scan in the lab.** `sh tools/run_experiment.sh` starts a capture, runs `python3 -m vscan ... --execute`, stops the capture, then runs `nmap -sS -Pn -n -p 22,80,443,8080 --max-retries 1 --max-rate 20 --reason` on the same ports: [lab run](evidence/lab-run.txt), [scanner result](evidence/result.json), [Nmap XML](evidence/nmap-validation.xml), [packet list](evidence/pcap-listing.txt).
5. **Repeat the scan.** The extension flag `--trials 5` repeats the bounded scan and reports a per-port consensus and whether it was stable: [five-trial result](evidence/extension-trials5.json).
6. **Model packet loss.** The lab never dropped a packet, so `python tools/evaluate_extension.py` simulates random loss with a fixed seed, 500 runs per case: [simulation table](evidence/extension-simulation.txt).

Install and try it: `pip install -r requirements.txt`, then step 2 and step 3. Step 4 needs the lab network and raw-socket permission, and the scanner refuses to send anywhere else.

## Results

| Finding | Evidence | Risk | Fix |
| --- | --- | --- | --- |
| `vscan` and Nmap agree on all four ports: 22, 80, 443 and 8080 are open (SYN/ACK). The scan took 0.395 s. | [result](evidence/result.json), [Nmap XML](evidence/nmap-validation.xml) | Informational. Open at TCP level only. TLS and the services themselves were not tested. | Follow with service and version detection before drawing conclusions about a service. |
| The capture shows 8 RST packets, while `vscan` reports sending 4. The extra four come from the lab container's own kernel: they follow the SYN/ACK within a millisecond and carry IP ID 0 and the DF flag, unlike the scanner's. | [packet list](evidence/pcap-listing.txt), [result](evidence/result.json) | Low. A reader of the capture alone would miscount the scanner's behaviour. | Block the kernel's automatic RST during the scan so the capture shows only the scanner's packets. |
| The 20 packets per second limit held. The scanner's own packets are about 51 ms apart in the capture. | [packet list](evidence/pcap-listing.txt) | Informational | None needed |
| Port 22 shows a 33 ms first response while the others show about 1 ms. The timer starts before the first send, which includes the ARP lookup. | [result](evidence/result.json) | Low. It makes the first round-trip time look slow. | Take the timestamp after the packet leaves. |
| Five trials gave the same four open ports every time, but sent 20 SYN and 20 RST instead of 4 and 4, and took 2.08 s instead of 0.40 s. | [five-trial result](evidence/extension-trials5.json), [result](evidence/result.json) | Informational. Repetition costs about five times as much traffic and time. | Use extra trials only where results can flip. |
| In the simulation at 20% loss, one trial gets 0.384 of 4 ports wrong per run and three trials get 0.142, at about three times the packets. | [simulation table](evidence/extension-simulation.txt) | Informational. The model covers random loss only. | Validate on a lab network with real loss. |
| All four lab ports were open, so closed, ICMP-filtered and silent ports were only exercised by the simulated tests. | [unit tests](evidence/unit-tests.txt), [lab run](evidence/lab-run.txt) | Medium. Three of the four classifications have no real-network evidence. | Repeat the experiment on a target with closed and filtered ports. |

Matching replies by address, ports and acknowledgement number (`ack == ISN + 1`), not just by port, is what let the scanner ignore the kernel's extra RSTs without miscounting. The Nmap comparison is the real check: it is an independent tool that reached the same four states.

Evidence notes: the original lab files were hashed with `sha256sum` (the hashes are in the [lab run](evidence/lab-run.txt)). The copies here have the container's MAC address redacted, so their hashes differ from the originals. The raw `.pcap` is not published, because the repository ignores capture files. The packet list is the text output from reading it. The screenshots are the terminal captures from my report with the Windows user path and the MAC address redacted.

<!-- figures -->

## What I would do differently

- Take the send timestamp after the packet leaves, so response times do not include the ARP lookup.
- Block the operating system's automatic RST during a scan so the capture shows exactly what the scanner sent.
- Run the experiment against a target with closed and filtered ports, so the real-network results cover all four states instead of only `open`.
- Wait for late duplicate replies before stopping a scan, since a scan currently stops as soon as every port has an answer.
