"""Build the Scapy packets (SYN and RST) and plan which probes will be sent."""
import hashlib
from dataclasses import dataclass, field

from scapy.layers.inet import IP, TCP

SYN_WINDOW = 1024  # TCP window put in every SYN
SYN_MSS = 1460     # TCP MSS option put in every SYN


@dataclass
class Probe:
    """One SYN we plan to send, plus what came back for it."""
    trial: int
    attempt: int
    port: int             # destination port being tested
    sport: int            # our own unique source port (how replies are matched)
    seq: int              # our initial sequence number
    sent_at: float = None
    first_response_at: float = None
    syn_ack: int = 0      # SYN/ACK replies received
    rst: int = 0          # RST replies received
    icmp: list = field(default_factory=list)  # (type, code, sender) of ICMP replies
    rst_sent: bool = False

    @property
    def answered(self):
        return bool(self.syn_ack or self.rst or self.icmp)


def derive_seq(scope_id, target, port, trial, attempt):
    """A repeatable 32-bit sequence number, different for every probe."""
    text = f"{scope_id}|{target}|{port}|{trial}|{attempt}".encode()
    return int.from_bytes(hashlib.sha256(text).digest()[:4], "big")


def plan_probes(scope_id, params):
    """Every probe the run may send, in send order. Each gets its own source port."""
    probes = []
    for trial in range(1, params.trials + 1):
        for attempt in range(1, params.attempts + 1):
            for port in params.ports:
                probes.append(Probe(trial, attempt, port,
                                    sport=params.source_port_base + len(probes),
                                    seq=derive_seq(scope_id, params.target, port, trial, attempt)))
    return probes


def build_syn(target, port, sport, seq, source_ip=None):
    """A TCP SYN from our sport to target:port."""
    return IP(dst=target, src=source_ip) / TCP(sport=sport, dport=port, flags="S", seq=seq,
                                               window=SYN_WINDOW, options=[("MSS", SYN_MSS)])


def build_rst(target, probe, source_ip=None):
    """The RST that closes the half-open connection after a SYN/ACK.
    Its sequence number is the SYN/ACK's ack number, which is our sequence number + 1."""
    seq = (probe.seq + 1) & 0xFFFFFFFF
    return IP(dst=target, src=source_ip) / TCP(sport=probe.sport, dport=probe.port, flags="R",
                                               seq=seq, window=0)
