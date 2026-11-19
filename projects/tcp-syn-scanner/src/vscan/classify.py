"""Turn the replies for a port into a state. Strongest evidence wins:
SYN/ACK > RST > ICMP unreachable > nothing. Silence is never called 'closed'."""
from collections import Counter
from dataclasses import dataclass

STATE_OPEN = "open"
STATE_CLOSED = "closed"
STATE_ICMP = "filtered-icmp-unreachable"
STATE_NONE = "filtered-or-no-response"
STATES = (STATE_OPEN, STATE_CLOSED, STATE_ICMP, STATE_NONE)  # strongest first


@dataclass(frozen=True)
class PortTrial:
    """Result for one port in one trial."""
    port: int
    trial: int
    state: str
    attempts_sent: int
    syn_ack_received: int
    rst_received: int
    icmp_unreachable: tuple     # (type, code, sender, count) entries
    duplicate_responses: int
    rst_sent: int
    conflicting_evidence: bool  # more than one kind of reply for this port
    rtt_ms: float = None


def classify_port_trial(port, trial, probes):
    sent = [p for p in probes if p.sent_at is not None]
    syn_ack = sum(p.syn_ack for p in sent)
    rst = sum(p.rst for p in sent)
    icmp = Counter(item for p in sent for item in p.icmp)

    if syn_ack:
        state = STATE_OPEN
    elif rst:
        state = STATE_CLOSED
    elif icmp:
        state = STATE_ICMP
    else:
        state = STATE_NONE

    duplicates = sum(max(0, p.syn_ack - 1) + max(0, p.rst - 1) + max(0, len(p.icmp) - 1) for p in sent)
    rtts = [(p.first_response_at - p.sent_at) * 1000 for p in sent if p.first_response_at is not None]
    return PortTrial(
        port=port,
        trial=trial,
        state=state,
        attempts_sent=len(sent),
        syn_ack_received=syn_ack,
        rst_received=rst,
        icmp_unreachable=tuple((kind, code, who, n) for (kind, code, who), n in sorted(icmp.items())),
        duplicate_responses=duplicates,
        rst_sent=sum(p.rst_sent for p in sent),
        conflicting_evidence=sum(bool(x) for x in (syn_ack, rst, icmp)) > 1,
        rtt_ms=round(min(rtts), 3) if rtts else None,
    )


def aggregate_states(states):
    """Most common state across trials (ties go to the stronger evidence), and whether all agreed."""
    counts = Counter(states)
    best = min(counts, key=lambda s: (-counts[s], STATES.index(s)))
    return best, len(counts) == 1
