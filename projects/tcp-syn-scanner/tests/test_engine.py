"""Scan behaviour against the deterministic simulated network."""

import unittest

import common  # noqa: F401
from common import SOURCE, TARGET, run_scan
from scapy.layers.inet import ICMP, IP, TCP
from scapy.packet import raw
from vscan.classify import STATE_CLOSED, STATE_ICMP, STATE_NONE, STATE_OPEN, aggregate_states
from vscan.packets import build_syn
from vscan.simnet import CLOSED, FILTERED, ICMP_PROHIBITED, OPEN, make_syn_ack


def by_port(outcome, trial=0):
    return {item.port: item for item in outcome.trials[trial]}


class ClassificationTests(unittest.TestCase):
    def test_open_closed_icmp_and_silent_ports_are_separated(self):
        outcome, net, _, _ = run_scan({22: OPEN, 80: CLOSED, 443: ICMP_PROHIBITED, 8080: FILTERED})
        ports = by_port(outcome)
        self.assertEqual(ports[22].state, STATE_OPEN)
        self.assertEqual(ports[80].state, STATE_CLOSED)
        self.assertEqual(ports[443].state, STATE_ICMP)
        self.assertEqual(ports[443].icmp_unreachable, ((3, 13, TARGET, 1),))
        self.assertEqual(ports[8080].state, STATE_NONE)

    def test_open_ports_are_closed_with_exactly_one_rst_each(self):
        outcome, net, _, _ = run_scan({22: OPEN, 80: OPEN, 443: CLOSED, 8080: FILTERED})
        rsts = net.rst_packets()
        self.assertEqual(sorted(p[TCP].dport for _, p in rsts), [22, 80])
        self.assertEqual(outcome.rst_sent, 2)
        probes = {p[TCP].dport: p[TCP] for _, p in net.syn_probes()}
        for _, rst in rsts:
            # RST sequence number must equal the SYN/ACK's ack, i.e. probe ISN + 1.
            self.assertEqual(rst[TCP].seq, probes[rst[TCP].dport].seq + 1)

    def test_missing_responses_are_retried_once_and_never_called_closed(self):
        outcome, net, clock, _ = run_scan({22: FILTERED, 80: OPEN, 443: OPEN, 8080: OPEN})
        silent = by_port(outcome)[22]
        self.assertEqual((silent.state, silent.attempts_sent), (STATE_NONE, 2))
        self.assertEqual(sum(1 for _, p in net.syn_probes() if p[TCP].dport == 22), 2)
        self.assertGreaterEqual(clock.now, 1.5)  # waited for the timeout before giving up

    def test_answered_ports_are_not_retried(self):
        outcome, net, _, _ = run_scan({22: OPEN, 80: CLOSED, 443: OPEN, 8080: CLOSED})
        self.assertTrue(all(item.attempts_sent == 1 for item in outcome.trials[0]))
        self.assertEqual(len(net.syn_probes()), 4)

    def test_loss_of_the_first_attempt_is_recovered_by_the_second(self):
        # Port 22 is silent for its first SYN and open afterwards.
        outcome, net, _, _ = run_scan({22: [FILTERED, OPEN], 80: OPEN, 443: OPEN, 8080: OPEN})
        item = by_port(outcome)[22]
        self.assertEqual((item.state, item.attempts_sent), (STATE_OPEN, 2))

    def test_attempts_never_exceed_the_limit(self):
        outcome, net, _, params = run_scan({22: FILTERED, 80: FILTERED, 443: FILTERED, 8080: FILTERED}, attempts=1)
        self.assertEqual(len(net.syn_probes()), 4)
        outcome, net, _, params = run_scan({22: FILTERED, 80: FILTERED, 443: FILTERED, 8080: FILTERED})
        self.assertEqual(len(net.syn_probes()), 8)


class UnrelatedDuplicateAndLateTests(unittest.TestCase):
    def test_unrelated_packets_never_change_results_but_are_counted(self):
        from common import make_scope
        from vscan.engine import Scanner
        from vscan.packets import plan_probes
        from vscan.scope import resolve_parameters
        from vscan.simnet import SimClock, SimulatedNetwork

        scope = make_scope()
        params = resolve_parameters(scope)
        first = plan_probes(scope.scope_id, params)[0]
        syn = build_syn(TARGET, first.port, first.sport, first.seq, SOURCE)
        wrong_ack = make_syn_ack(TARGET, SOURCE, syn)
        wrong_ack[TCP].ack += 1
        from_stranger = make_syn_ack("172.28.70.3", SOURCE, syn)
        echo = IP(src=TARGET, dst=SOURCE) / ICMP(type=0)
        clock = SimClock()
        net = SimulatedNetwork(clock, TARGET, SOURCE, {22: FILTERED, 80: FILTERED, 443: FILTERED, 8080: FILTERED})
        for packet in (wrong_ack, from_stranger, echo):
            net.inject(IP(raw(packet)), 0.001)
        outcome = Scanner(scope.scope_id, params, net, clock, SOURCE).run()
        self.assertEqual(outcome.unmatched_packets, 3)
        self.assertTrue(all(item.state == STATE_NONE for item in outcome.trials[0]))
        self.assertEqual(outcome.rst_sent, 0)

    def test_duplicate_syn_ack_is_counted_once_as_evidence_and_closed_once(self):
        outcome, net, _, _ = run_scan(
            {22: OPEN, 80: OPEN, 443: CLOSED, 8080: CLOSED}, net_kwargs={"duplicate_ports": [22]}
        )
        item = by_port(outcome)[22]
        self.assertEqual(item.state, STATE_OPEN)
        self.assertEqual((item.syn_ack_received, item.duplicate_responses, item.rst_sent), (2, 1, 1))
        self.assertEqual(sum(1 for _, p in net.rst_packets() if p[TCP].dport == 22), 1)

    def test_a_late_reply_is_matched_to_the_attempt_that_provoked_it(self):
        # Latency exceeds the 1.5 s timeout, so attempt 2 is sent before attempt 1's reply arrives.
        outcome, net, _, _ = run_scan(
            {22: OPEN, 80: OPEN, 443: OPEN, 8080: OPEN}, net_kwargs={"latency": 1.7}
        )
        item = by_port(outcome)[22]
        self.assertEqual(item.state, STATE_OPEN)
        self.assertEqual(item.attempts_sent, 2)
        self.assertEqual(item.rst_sent, item.syn_ack_received)  # every SYN/ACK was closed, none confused

    def test_conflicting_evidence_is_flagged_and_open_wins(self):
        from common import make_scope
        from vscan.engine import Scanner
        from vscan.packets import plan_probes
        from vscan.scope import resolve_parameters
        from vscan.simnet import SimClock, SimulatedNetwork, make_rst_ack

        scope = make_scope()
        params = resolve_parameters(scope, ports=[22, 80])
        first_attempt = plan_probes(scope.scope_id, params)[0]  # port 22, attempt 1
        clock = SimClock()
        # Attempt 1 is unanswered; attempt 2 gets a SYN/ACK; then a late RST for attempt 1 arrives.
        net = SimulatedNetwork(clock, TARGET, SOURCE, {22: [FILTERED, OPEN], 80: FILTERED})
        late_rst = make_rst_ack(TARGET, SOURCE, build_syn(TARGET, 22, first_attempt.sport, first_attempt.seq, SOURCE))
        net.inject(IP(raw(late_rst)), 1.56)
        outcome = Scanner(scope.scope_id, params, net, clock, SOURCE).run()
        item = by_port(outcome)[22]
        self.assertEqual((item.state, item.syn_ack_received, item.rst_received), (STATE_OPEN, 1, 1))
        self.assertTrue(item.conflicting_evidence)


class RateLimitTests(unittest.TestCase):
    def test_no_two_transmissions_are_closer_than_the_rate_allows(self):
        outcome, net, _, _ = run_scan({22: OPEN, 80: OPEN, 443: OPEN, 8080: OPEN}, trials=2)
        times = [t for t, _ in net.sent]
        self.assertGreater(len(times), 8)  # SYNs and RSTs both counted
        gaps = [b - a for a, b in zip(times, times[1:])]
        self.assertGreaterEqual(min(gaps), 1 / 20 - 1e-9)

    def test_a_lower_requested_rate_is_honoured(self):
        outcome, net, _, _ = run_scan({22: CLOSED, 80: CLOSED, 443: CLOSED, 8080: CLOSED}, rate_pps=4)
        times = [t for t, _ in net.sent]
        self.assertGreaterEqual(min(b - a for a, b in zip(times, times[1:])), 0.25 - 1e-9)


class TrialAggregationTests(unittest.TestCase):
    def test_consensus_and_stability(self):
        self.assertEqual(aggregate_states([STATE_OPEN, STATE_OPEN]), (STATE_OPEN, True))
        self.assertEqual(aggregate_states([STATE_NONE, STATE_OPEN, STATE_OPEN]), (STATE_OPEN, False))
        self.assertEqual(aggregate_states([STATE_NONE, STATE_OPEN]), (STATE_OPEN, False))  # tie -> stronger evidence

    def test_trials_use_distinct_source_ports_and_flag_unstable_ports(self):
        outcome, net, _, _ = run_scan(
            {22: [OPEN, FILTERED, FILTERED, FILTERED, FILTERED, FILTERED], 80: OPEN, 443: CLOSED, 8080: FILTERED},
            trials=3,
            attempts=1,
        )
        sports = [p[TCP].sport for _, p in net.syn_probes()]
        self.assertEqual(len(sports), len(set(sports)))
        states = [by_port(outcome, t)[22].state for t in range(3)]
        self.assertEqual(states, [STATE_OPEN, STATE_NONE, STATE_NONE])
        self.assertEqual(aggregate_states(states), (STATE_NONE, False))
        self.assertEqual([by_port(outcome, t)[80].state for t in range(3)], [STATE_OPEN] * 3)


if __name__ == "__main__":
    unittest.main()
