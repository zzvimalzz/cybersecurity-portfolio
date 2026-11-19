"""Probe construction and response matching."""

import unittest

import common  # noqa: F401
from common import SOURCE, TARGET, make_scope
from scapy.layers.inet import ICMP, IP, TCP
from scapy.layers.l2 import ARP
from scapy.packet import raw
from vscan.matching import KIND_ICMP, KIND_RST, KIND_SYN_ACK, match_reply
from vscan.packets import build_rst, build_syn, derive_seq, plan_probes
from vscan.scope import resolve_parameters
from vscan.simnet import make_icmp_unreachable, make_rst_ack, make_syn_ack


def sent_probe(port=80, sport=40001, seq=1000):
    from vscan.packets import Probe

    return Probe(trial=1, attempt=1, port=port, sport=sport, seq=seq, sent_at=0.0)


class ConstructionTests(unittest.TestCase):
    def test_syn_has_the_requested_fields_and_survives_serialisation(self):
        packet = IP(raw(build_syn(TARGET, 443, 40003, 123456, SOURCE)))
        self.assertEqual((packet.src, packet.dst), (SOURCE, TARGET))
        self.assertEqual((packet[TCP].sport, packet[TCP].dport, packet[TCP].seq), (40003, 443, 123456))
        self.assertEqual(int(packet[TCP].flags), 0x02)

    def test_rst_uses_the_synack_acknowledgement_as_its_sequence_number(self):
        probe = sent_probe(seq=1000)
        rst = IP(raw(build_rst(TARGET, probe, SOURCE)))
        self.assertEqual(int(rst[TCP].flags), 0x04)
        self.assertEqual((rst[TCP].seq, rst[TCP].sport, rst[TCP].dport), (1001, probe.sport, probe.port))

    def test_plan_gives_every_probe_a_unique_source_port_and_isn(self):
        params = resolve_parameters(make_scope(), trials=3)
        probes = plan_probes("scope", params)
        self.assertEqual(len(probes), 3 * 4 * 2)
        self.assertEqual(len({p.sport for p in probes}), len(probes))
        self.assertEqual(len({p.seq for p in probes}), len(probes))
        self.assertEqual([p.sport for p in probes], [p.sport for p in plan_probes("scope", params)])

    def test_isn_is_deterministic_but_depends_on_every_input(self):
        base = derive_seq("s", TARGET, 80, 1, 1)
        self.assertEqual(base, derive_seq("s", TARGET, 80, 1, 1))
        for other in [derive_seq("t", TARGET, 80, 1, 1), derive_seq("s", TARGET, 81, 1, 1), derive_seq("s", TARGET, 80, 2, 1), derive_seq("s", TARGET, 80, 1, 2)]:
            self.assertNotEqual(base, other)


class MatchingTests(unittest.TestCase):
    def setUp(self):
        self.probe = sent_probe()
        self.index = {self.probe.sport: self.probe}
        self.syn = build_syn(TARGET, self.probe.port, self.probe.sport, self.probe.seq, SOURCE)

    def match(self, packet):
        return match_reply(IP(raw(packet)), self.index, TARGET, SOURCE)

    def test_syn_ack_and_rst_are_matched_to_the_probe(self):
        observation = self.match(make_syn_ack(TARGET, SOURCE, self.syn))
        self.assertEqual((observation.kind, observation.probe), (KIND_SYN_ACK, self.probe))
        observation = self.match(make_rst_ack(TARGET, SOURCE, self.syn))
        self.assertEqual((observation.kind, observation.probe), (KIND_RST, self.probe))

    def test_wrong_acknowledgement_is_unrelated(self):
        reply = make_syn_ack(TARGET, SOURCE, self.syn)
        reply[TCP].ack += 5
        self.assertIsNone(self.match(reply))

    def test_wrong_port_source_or_destination_is_unrelated(self):
        reply = make_syn_ack(TARGET, SOURCE, self.syn)
        spoofed_port = reply.copy()
        spoofed_port[TCP].sport = 81
        other_host = reply.copy()
        other_host[IP].src = "172.28.70.3"
        other_dest = reply.copy()
        other_dest[IP].dst = "172.28.70.99"
        unknown_sport = reply.copy()
        unknown_sport[TCP].dport = 55555
        for packet in (spoofed_port, other_host, other_dest, unknown_sport):
            self.assertIsNone(self.match(packet))

    def test_rst_without_ack_and_bare_syn_are_unrelated(self):
        bare_rst = IP(src=TARGET, dst=SOURCE) / TCP(sport=80, dport=self.probe.sport, flags="R", ack=0)
        self.assertIsNone(self.match(bare_rst))
        syn = IP(src=TARGET, dst=SOURCE) / TCP(sport=80, dport=self.probe.sport, flags="S")
        self.assertIsNone(self.match(syn))

    def test_replies_to_a_probe_never_sent_are_unrelated(self):
        self.probe.sent_at = None
        self.assertIsNone(self.match(make_syn_ack(TARGET, SOURCE, self.syn)))

    def test_non_ip_and_unrelated_icmp_are_ignored(self):
        self.assertIsNone(match_reply(ARP(), self.index, TARGET, SOURCE))
        echo = IP(src=TARGET, dst=SOURCE) / ICMP(type=0)
        self.assertIsNone(self.match(echo))

    def test_icmp_unreachable_is_matched_from_the_quoted_header_only(self):
        reply = make_icmp_unreachable("172.28.70.1", SOURCE, self.syn, code=13, quote_bytes=8)
        observation = match_reply(reply, self.index, TARGET, SOURCE)
        self.assertEqual((observation.kind, observation.icmp_type, observation.icmp_code), (KIND_ICMP, 3, 13))
        self.assertEqual(observation.source, "172.28.70.1")
        self.assertIs(observation.probe, self.probe)

    def test_icmp_quoting_someone_elses_traffic_is_unrelated(self):
        other = build_syn(TARGET, self.probe.port, self.probe.sport, self.probe.seq + 1, SOURCE)
        self.assertIsNone(match_reply(make_icmp_unreachable(TARGET, SOURCE, other), self.index, TARGET, SOURCE))
        elsewhere = build_syn("172.28.70.3", self.probe.port, self.probe.sport, self.probe.seq, SOURCE)
        self.assertIsNone(match_reply(make_icmp_unreachable(TARGET, SOURCE, elsewhere), self.index, TARGET, SOURCE))


if __name__ == "__main__":
    unittest.main()
