"""A fake network for the tests and the extension evaluation (no real sockets).
Each port is told how to behave; loss and duplicates are seeded, so every run is identical."""
import heapq
import random

from scapy.layers.inet import ICMP, IP, TCP
from scapy.packet import raw

OPEN = "open"
CLOSED = "closed"
FILTERED = "filtered"              # silent drop
ICMP_PROHIBITED = "icmp-prohibited"


class SimClock:
    def __init__(self):
        self.now = 0.0

    def monotonic(self):
        return self.now


def make_syn_ack(target, source_ip, probe_packet):
    tcp = probe_packet[TCP]
    return IP(src=target, dst=source_ip) / TCP(sport=tcp.dport, dport=tcp.sport, flags="SA",
                                               seq=5000, ack=(tcp.seq + 1) & 0xFFFFFFFF)


def make_rst_ack(target, source_ip, probe_packet):
    tcp = probe_packet[TCP]
    return IP(src=target, dst=source_ip) / TCP(sport=tcp.dport, dport=tcp.sport, flags="RA",
                                               seq=0, ack=(tcp.seq + 1) & 0xFFFFFFFF)


def make_icmp_unreachable(sender, source_ip, probe_packet, code=13, quote_bytes=8):
    """ICMP 'destination unreachable' quoting our IP header plus the first bytes of our TCP header."""
    quoted = raw(probe_packet)[:20 + quote_bytes]
    built = IP(src=sender, dst=source_ip) / ICMP(type=3, code=code) / quoted
    return IP(raw(built))   # re-read it, so the quote parses as IPerror/TCPerror like on a real wire


class SimulatedNetwork:
    """behaviour = {port: "open" | "closed" | "filtered" | "icmp-prohibited" | [one per SYN received]}"""

    def __init__(self, clock, target, source_ip, behaviour, *, loss=0.0, duplicate_ports=(),
                 latency=0.002, seed=0):
        self.clock = clock
        self.target = target
        self.source_ip = source_ip
        self.behaviour = behaviour
        self.loss = loss                          # chance each packet is lost, in each direction
        self.duplicate_ports = set(duplicate_ports)
        self.latency = latency
        self.rng = random.Random(seed)
        self.syn_count = {}                       # SYNs received per port so far
        self.arriving = []                        # (arrival time, number, packet) waiting to be read
        self.number = 0
        self.sent = []                            # (time, packet) for everything the scanner sent

    def inject(self, packet, delay=0.0):
        """Make any packet arrive `delay` seconds from now."""
        self.number += 1
        heapq.heappush(self.arriving, (self.clock.now + delay, self.number, packet))

    def action_for(self, port):
        action = self.behaviour.get(port, FILTERED)
        count = self.syn_count.get(port, 0)
        self.syn_count[port] = count + 1
        return action if isinstance(action, str) else action[min(count, len(action) - 1)]

    def send(self, packet):
        self.sent.append((self.clock.now, packet))
        tcp = packet[TCP]
        if int(tcp.flags) != 0x02:                # only SYNs get a reply
            return
        action = self.action_for(tcp.dport)
        if self.rng.random() < self.loss:         # SYN lost on the way out
            return
        if action == OPEN:
            reply = make_syn_ack(self.target, self.source_ip, packet)
        elif action == CLOSED:
            reply = make_rst_ack(self.target, self.source_ip, packet)
        elif action == ICMP_PROHIBITED:
            reply = make_icmp_unreachable(self.target, self.source_ip, packet)
        else:
            return
        if self.rng.random() < self.loss:         # reply lost on the way back
            return
        self.inject(reply, self.latency)
        if tcp.dport in self.duplicate_ports:
            self.inject(reply, self.latency * 2)

    def receive(self, timeout):
        deadline = self.clock.now + timeout
        if self.arriving and self.arriving[0][0] <= deadline:
            arrival, _, packet = heapq.heappop(self.arriving)
            self.clock.now = max(self.clock.now, arrival)
            return packet
        self.clock.now = deadline                 # nothing arrived: time passes
        return None

    # helpers the tests use
    def syn_probes(self):
        return [(t, p) for t, p in self.sent if int(p[TCP].flags) == 0x02]

    def rst_packets(self):
        return [(t, p) for t, p in self.sent if int(p[TCP].flags) == 0x04]
