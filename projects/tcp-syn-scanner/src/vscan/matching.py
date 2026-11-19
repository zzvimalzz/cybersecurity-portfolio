"""Decide whether a captured packet is a real reply to one of our probes."""
from dataclasses import dataclass

from scapy.layers.inet import ICMP, IP, TCP, IPerror, TCPerror

KIND_SYN_ACK = "syn-ack"
KIND_RST = "rst"
KIND_ICMP = "icmp-unreachable"

FIN, SYN, RST, ACK = 0x01, 0x02, 0x04, 0x10  # TCP flag bits


@dataclass(frozen=True)
class Observation:
    kind: str
    probe: object
    source: str
    icmp_type: int = None
    icmp_code: int = None


def match_reply(packet, probes_by_sport, target, source_ip):
    """Return an Observation if packet answers one of our probes, otherwise None."""
    if not packet.haslayer(IP) or (source_ip and packet[IP].dst != source_ip):
        return None
    if packet.haslayer(ICMP):
        return match_icmp(packet, probes_by_sport, target, source_ip)
    if packet.haslayer(TCP):
        return match_tcp(packet, probes_by_sport, target)
    return None


def match_tcp(packet, probes_by_sport, target):
    ip, tcp = packet[IP], packet[TCP]
    probe = probes_by_sport.get(tcp.dport)          # our source port identifies the probe
    if ip.src != target or probe is None or probe.sent_at is None or tcp.sport != probe.port:
        return None
    flags = int(tcp.flags)
    if not flags & ACK or tcp.ack != (probe.seq + 1) & 0xFFFFFFFF:  # must acknowledge OUR sequence number
        return None
    if flags & RST and not flags & (SYN | FIN):
        return Observation(KIND_RST, probe, ip.src)
    if flags & SYN and not flags & (FIN | RST):
        return Observation(KIND_SYN_ACK, probe, ip.src)
    return None


def match_icmp(packet, probes_by_sport, target, source_ip):
    icmp = packet[ICMP]
    if icmp.type != 3 or not (packet.haslayer(IPerror) and packet.haslayer(TCPerror)):
        return None
    inner_ip, inner_tcp = packet[IPerror], packet[TCPerror]   # the quoted copy of OUR packet
    probe = probes_by_sport.get(inner_tcp.sport)
    if inner_ip.dst != target or (source_ip and inner_ip.src != source_ip):
        return None
    if probe is None or probe.sent_at is None:
        return None
    if inner_tcp.dport != probe.port or inner_tcp.seq != probe.seq:
        return None
    return Observation(KIND_ICMP, probe, packet[IP].src, int(icmp.type), int(icmp.code))
