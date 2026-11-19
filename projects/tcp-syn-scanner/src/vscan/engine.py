"""The scan loop: send SYNs at a limited rate, read replies, retry, close with RST.

Rule that is always kept: any two packets we send (SYN or RST) are at least
1/rate seconds apart, and a port gets at most `attempts` SYNs per trial.
"""
import time
from collections import deque
from dataclasses import dataclass

from .classify import classify_port_trial
from .matching import KIND_ICMP, KIND_RST, KIND_SYN_ACK, match_reply
from .packets import build_rst, build_syn, plan_probes


class RealClock:
    def monotonic(self):
        return time.monotonic()


@dataclass(frozen=True)
class ScanOutcome:
    trials: tuple          # trials[t][i] = PortTrial for port i in trial t
    syn_sent: int
    rst_sent: int
    unmatched_packets: int
    start_mono: float
    end_mono: float


class Scanner:
    """transport needs send(packet) and receive(timeout); clock needs monotonic()."""

    def __init__(self, scope_id, params, transport, clock, source_ip=None):
        self.params = params
        self.transport = transport
        self.clock = clock
        self.source_ip = source_ip
        self.probes = plan_probes(scope_id, params)
        self.probes_by_sport = {p.sport: p for p in self.probes}
        self.interval = 1 / params.rate_pps   # minimum gap between our packets
        self.next_allowed = 0.0               # earliest time we may send again
        self.rst_queue = deque()              # probes waiting for their RST
        self.syn_sent = self.rst_sent = self.unmatched = 0

    # ---- reading replies ----

    def handle(self, packet):
        found = match_reply(packet, self.probes_by_sport, self.params.target, self.source_ip)
        if found is None:
            self.unmatched += 1
            return
        probe = found.probe
        if probe.first_response_at is None:
            probe.first_response_at = self.clock.monotonic()
        if found.kind == KIND_SYN_ACK:
            probe.syn_ack += 1
            if probe.syn_ack == 1:
                self.rst_queue.append(probe)   # first SYN/ACK: close it with one RST
        elif found.kind == KIND_RST:
            probe.rst += 1
        elif found.kind == KIND_ICMP:
            probe.icmp.append((found.icmp_type, found.icmp_code, found.source))

    # ---- sending, with the rate limit ----

    def send(self, packet):
        self.transport.send(packet)
        self.next_allowed = self.clock.monotonic() + self.interval

    def pump(self, until, done=lambda: False):
        """Read replies and send queued RSTs until time `until` (or until done() is true)."""
        while True:
            now = self.clock.monotonic()
            if self.rst_queue and now >= self.next_allowed:
                probe = self.rst_queue.popleft()
                self.send(build_rst(self.params.target, probe, self.source_ip))
                probe.rst_sent = True
                self.rst_sent += 1
            elif not self.rst_queue and (now >= until or done()):
                return
            else:
                wake = self.next_allowed if self.rst_queue else until
                packet = self.transport.receive(max(0, wake - now))
                if packet is not None:
                    self.handle(packet)

    def wait_for_slot(self):
        """Wait until the rate limit allows another packet."""
        while True:
            self.pump(self.next_allowed)
            if self.clock.monotonic() >= self.next_allowed:
                return

    def send_syn(self, probe):
        packet = build_syn(self.params.target, probe.port, probe.sport, probe.seq, self.source_ip)
        probe.sent_at = self.clock.monotonic()   # set BEFORE sending so a fast reply can match
        self.send(packet)
        self.syn_sent += 1

    # ---- the scan ----

    def select(self, trial, port=None, attempt=None):
        return [p for p in self.probes
                if p.trial == trial and port in (None, p.port) and attempt in (None, p.attempt)]

    def answered(self, trial, port):
        return any(p.answered for p in self.select(trial, port))

    def trial_done(self, trial):
        return all(self.answered(trial, port) for port in self.params.ports)

    def run(self):
        params = self.params
        start = self.clock.monotonic()
        for trial in range(1, params.trials + 1):
            for attempt in range(1, params.attempts + 1):
                sent_any = False
                for probe in self.select(trial, attempt=attempt):
                    self.wait_for_slot()
                    if not self.answered(trial, probe.port):   # only (re)try silent ports
                        self.send_syn(probe)
                        sent_any = True
                if not sent_any:
                    break
                self.pump(self.clock.monotonic() + params.timeout_seconds,
                          done=lambda t=trial: self.trial_done(t))
                if self.trial_done(trial):
                    break
        self.pump(self.clock.monotonic())   # send any RSTs still waiting
        end = self.clock.monotonic()

        results = tuple(
            tuple(classify_port_trial(port, trial, self.select(trial, port)) for port in params.ports)
            for trial in range(1, params.trials + 1))
        return ScanOutcome(results, self.syn_sent, self.rst_sent, self.unmatched, start, end)
