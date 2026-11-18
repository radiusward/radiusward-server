# Copyright 2026 The radiusward Authors
# SPDX-License-Identifier: Apache-2.0
"""Unit tests of the benchmark harness's decisions (scripts/bench.py): parsing the generators' summaries, the verdict
of a step, and the ladder's climb, bisection and load-limited retries, with fake generators instead of containers.

  python3 -m unittest discover -s scripts/tests
"""

import importlib.util
import os
import subprocess
import types
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))


def load(name, file):
    spec = importlib.util.spec_from_file_location(name, os.path.join(HERE, "..", file))
    module = importlib.util.module_from_spec(spec)
    # the harness asks docker which compose it has when imported; no docker is needed here
    with mock.patch.object(subprocess, "run", return_value=subprocess.CompletedProcess([], 0, "", "")):
        spec.loader.exec_module(module)
    return module


bench = load("bench", "bench.py")


def load_line(sent, acked, failed, seconds, p50, p99):
    return (f"load: sent {sent}, acked {acked}, failed {failed}, retransmissions 0 in {seconds}s "
            f"({acked / seconds:.1f} req/s); latency p50 {p50} ms, p99 {p99} ms, max {p99 * 2} ms")


def access_line(sent, accepted, rejected, timeouts, p50, p99):
    return (f"access: sent {sent} ({rejected} with a wrong password), accepted {accepted}, rejected {rejected}, "
            f"challenged 0, timeouts {timeouts}, unexpected 0; latency p50 {p50} ms, p99 {p99} ms")


class ParsingTest(unittest.TestCase):

    def test_sizes_from_docker_stats(self):
        self.assertEqual(bench.parse_size("512MiB"), 512 << 20)
        self.assertEqual(bench.parse_size("1.5GiB"), int(1.5 * (1 << 30)))
        self.assertEqual(bench.parse_size("20kB"), 20_000)
        self.assertEqual(bench.parse_size("—"), 0)

    def test_generator_summaries_are_combined_into_one_step(self):
        outputs = ["noise\n" + load_line(6000, 6000, 0, 60, 2.0, 9.0), load_line(6000, 5900, 2, 60, 4.0, 30.0)]
        step = bench.combine(outputs, 200, "accounting", 60)
        self.assertEqual(step["accounting"]["sent"], 12000)
        self.assertEqual(step["accounting"]["acked"], 11900)
        self.assertEqual(step["accounting"]["failed"], 2)
        self.assertEqual(step["accounting"]["rps"], round(11900 / 60, 1), "answered requests over the step's length")
        self.assertEqual(step["accounting"]["p50_ms"], 3.0, "median of the generators")
        self.assertEqual(step["p99_ms"], 30.0, "the worst generator")
        self.assertEqual(step["generators"], 2)

    def test_access_answers_count_accepted_rejected_and_challenged(self):
        step = bench.combine([access_line(1000, 900, 100, 0, 1.0, 4.0)], 20, "access", 50)
        self.assertEqual(step["access"]["rps"], 20.0)
        self.assertEqual(step["rps"], 20.0)
        mixed = bench.combine([load_line(700, 700, 0, 10, 1.0, 5.0) + "\n" + access_line(300, 300, 0, 0, 1.0, 7.0)],
                              100, "mix", 10)
        self.assertEqual(mixed["rps"], 100.0)
        self.assertEqual(mixed["p99_ms"], 7.0)

    def test_a_step_without_summary_is_an_error(self):
        step = bench.combine(["Error: no such image\n", ""], 100, "accounting", 10)
        self.assertIn("no generator summary: Error: no such image", step["error"])
        self.assertIsNone(step["p99_ms"])


class VerdictTest(unittest.TestCase):

    def step(self, **kw):
        s = {"target_rps": 1000, "rps": 1000.0, "p99_ms": 10.0}
        s.update(kw)
        return s

    def test_a_good_step_passes(self):
        self.assertEqual(bench.verdict(self.step(), 500), ([], False))

    def test_lost_requests_latency_and_errors_are_the_servers(self):
        for step, text in ((self.step(accounting={"failed": 3}), "3 accounting requests lost"),
                           (self.step(access={"timeouts": 2}), "2 Access-Request timeouts"),
                           (self.step(p99_ms=900.0), "p99 900.0 ms > 500 ms"),
                           (self.step(error="no generator summary"), "no generator summary")):
            reasons, load_limited = bench.verdict(step, 500)
            self.assertTrue(any(text in r for r in reasons), reasons)
            self.assertFalse(load_limited)

    def test_short_of_the_rate_with_latency_fine_is_load_limited(self):
        reasons, load_limited = bench.verdict(self.step(rps=600.0), 500)
        self.assertEqual(reasons, ["only 600.0 of 1000 requests/s arrived"])
        self.assertTrue(load_limited)
        self.assertEqual(bench.verdict(self.step(rps=950.0), 500), ([], False), "within 10 %")

    def test_short_of_the_rate_and_slow_is_not_load_limited(self):
        reasons, load_limited = bench.verdict(self.step(rps=600.0, p99_ms=800.0), 500)
        self.assertEqual(len(reasons), 2)
        self.assertFalse(load_limited)


class FakeStack:
    remote = True

    def member_urls(self):
        return []

    def server_urls(self):
        return []


class LadderTest(unittest.TestCase):
    """The ladder against a fake system: radiusward carries `capacity` requests/s, each generator sends at most
    `per_generator` requests/s."""

    def run_ladder(self, steps, capacity, per_generator, generators=1, max_generators=4, resolution=0.1):
        calls = []

        def fake_generators(workload, rate, seconds, count, image, first_session, interim):
            calls.append((rate, count, first_session))
            arrived = min(rate, count * per_generator)
            answered = min(arrived, capacity)
            p99 = 20.0 if arrived <= capacity else 2000.0
            return [load_line(int(arrived * seconds / count), int(answered * seconds / count), 0, seconds, 2.0, p99)
                    for _ in range(count)]

        args = types.SimpleNamespace(duration=10, interim=60, generators=generators, max_generators=max_generators,
                                     resolution=resolution, p99_limit=500.0, pause=0)
        with mock.patch.object(bench, "STACK", FakeStack()), \
                mock.patch.object(bench, "generators", fake_generators), \
                mock.patch.object(bench, "scrape", lambda url: {}), \
                mock.patch.object(bench, "log", lambda msg: None), \
                mock.patch.object(bench.time, "sleep", lambda s: None):
            result = bench.ladder("accounting", steps, args, "image", 400_000_000)
        return result, calls

    def test_climbs_until_a_step_fails_then_bisects_to_the_resolution(self):
        result, calls = self.run_ladder([1000, 2000, 4000, 8000], capacity=5000, per_generator=100_000)
        self.assertFalse(result["load_limited"])
        self.assertGreaterEqual(result["ceiling_rps"], 4500, "within 10 % of the capacity")
        self.assertLessEqual(result["ceiling_rps"], 5000)
        self.assertIn("p99", result["stopped_by"])
        rates = [r for r, _, _ in calls]
        self.assertEqual(rates[:4], [1000, 2000, 4000, 8000])
        self.assertTrue(all(r % 50 == 0 for r in rates), "bisection rates are rounded to 50/s")
        self.assertEqual(len({s for _, _, s in calls}), len(calls), "every probe uses its own session ids")

    def test_every_step_passing_leaves_the_ceiling_open(self):
        result, calls = self.run_ladder([1000, 2000], capacity=10_000, per_generator=100_000)
        self.assertEqual(result["ceiling_rps"], 2000.0)
        self.assertIsNone(result["stopped_by"])
        self.assertEqual(len(calls), 2)

    def test_a_rate_the_generators_cannot_send_is_retried_with_twice_as_many(self):
        result, calls = self.run_ladder([1000, 2000, 4000], capacity=100_000, per_generator=1500)
        self.assertEqual([(r, c) for r, c, _ in calls], [(1000, 1), (2000, 1), (2000, 2), (4000, 2), (4000, 4)])
        self.assertFalse(result["load_limited"], "four generators send 4000/s")
        self.assertEqual(result["ceiling_rps"], 4000.0)

    def test_still_short_with_the_most_generators_stops_with_a_lower_bound(self):
        result, calls = self.run_ladder([1000, 4000, 8000], capacity=100_000, per_generator=1500, max_generators=2)
        self.assertTrue(result["load_limited"])
        self.assertEqual(result["ceiling_rps"], 3000.0, "what arrived and was answered: a lower bound")
        self.assertIn("only 3000.0 of 4000", result["stopped_by"])
        self.assertNotIn(8000, [r for r, _, _ in calls], "no higher rate after a load-limited step")

    def test_the_number_of_probes_is_capped(self):
        result, calls = self.run_ladder(list(range(100, 10_000, 100)), capacity=100_000, per_generator=100_000)
        self.assertEqual(len(calls), bench.MAX_PROBES)


if __name__ == "__main__":
    unittest.main()
