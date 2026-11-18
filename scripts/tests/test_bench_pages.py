# Copyright 2026 The radiusward Authors
# SPDX-License-Identifier: Apache-2.0
"""Unit tests of the benchmark pages (scripts/bench-pages.py): the helpers that word a result, and a whole page built
from a published run (bench-20261111T183531Z.json, GitHub runner, 2026-11-11)."""

import copy
import importlib.util
import json
import os
import shutil
import sys
import tempfile
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
FIXTURE = os.path.join(HERE, "bench-20261111T183531Z.json")

spec = importlib.util.spec_from_file_location("bench_pages", os.path.join(HERE, "..", "bench-pages.py"))
pages = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pages)


class HelpersTest(unittest.TestCase):

    def test_numbers(self):
        self.assertEqual(pages.fmt(15052.8), "15,053")
        self.assertEqual(pages.fmt(None), "–")
        self.assertEqual(pages.ms(2.345), "2.3")
        self.assertEqual(pages.ms(609.3), "609")

    def test_reasons_in_plain_words(self):
        self.assertEqual(pages.pretty("p99 609.3 ms > 500.0 ms"), "p99 609 ms, over 500 ms")
        self.assertEqual(pages.pretty("only 3000.0 of 4000 requests/s arrived"), "only 3,000 of 4,000/s answered")
        self.assertEqual(pages.pretty("3 accounting requests lost"), "3 accounting requests lost")

    def test_a_rate_probed_again_shows_its_last_probe(self):
        steps = [{"target_rps": 2000, "generators": 1}, {"target_rps": 1000}, {"target_rps": 2000, "generators": 2}]
        self.assertEqual(pages.per_rate(steps), [{"target_rps": 1000}, {"target_rps": 2000, "generators": 2}])

    def test_memory_of_runs_before_and_after_the_rename(self):
        def run(name):
            steps = [{"containers": {name: {"mem_max_bytes": 300 * 2**20}, "node-0": {"mem_max_bytes": 600 * 2**20}}}]
            return {"workloads": {"accounting": {"steps": steps}}, "environment": {"profile": "small"}}
        for name in ("gateway-a", "server-a"):
            note = pages.memory_note(run(name))
            self.assertIn("each RADIUS server at most 300 MiB", note, name)
            self.assertIn("each cluster member at most 600 MiB", note, name)

    def test_lower_bounds(self):
        self.assertTrue(pages.lower_bound({"load_limited": True, "stopped_by": "only …"}))
        self.assertTrue(pages.lower_bound({"load_limited": False, "stopped_by": None}), "every step passed")
        self.assertFalse(pages.lower_bound({"load_limited": False, "stopped_by": "p99 …"}))
        self.assertFalse(pages.lower_bound({"ceiling_rps": 5}), "schema 1 records no stopped_by")
        self.assertEqual(pages.ceiling_text({"ceiling_rps": 15052.8, "load_limited": True}), "≥ 15,053/s")
        self.assertEqual(pages.ceiling_text({"ceiling_rps": 3730.8, "stopped_by": "p99"}), "3,731/s")

    def test_the_featured_run_prefers_dedicated_machines(self):
        shared = {"environment": {"shared_host": True, "date": "2"}}
        dedicated = {"environment": {"date": "1"}}
        self.assertIs(pages.featured([dedicated, shared]), dedicated)
        self.assertIs(pages.featured([shared]), shared)


class PageTest(unittest.TestCase):

    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.dir)
        self.results = os.path.join(self.dir, "results", "bench-run")
        self.site = os.path.join(self.dir, "site")
        os.makedirs(self.results)
        shutil.copy(FIXTURE, self.results)

    def build(self):
        with mock.patch.object(sys, "argv", ["bench-pages.py", os.path.join(self.dir, "results"), self.site]), \
                mock.patch("builtins.print"):
            pages.main()
        page = os.path.join(self.site, "benchmarks", "index.html")
        if not os.path.exists(page):
            return None
        with open(page) as f:
            return f.read()

    def test_a_page_the_latest_summary_and_the_badge(self):
        page = self.build()
        self.assertIn("≥ 15,053/s", page, "authentication was load-limited: a lower bound")
        self.assertIn("3,731/s", page)
        self.assertIn('<div class="scroll"><table>', page, "tables scroll on a phone")
        self.assertNotRegex(page, r"\{(sections|trend|description)\}", "no template field left unfilled")
        latest = json.load(open(os.path.join(self.site, "benchmarks", "latest.json")))
        self.assertEqual(latest["where"], "github-ubuntu-24.04")
        self.assertEqual(latest["ceilings"]["accounting"], 3730.8)
        self.assertEqual(latest["load_limited"], {"accounting": False, "access": True, "mix": False})
        self.assertIs(latest["failover_lost"], False)
        self.assertEqual(latest["runs"], 1)
        badge = json.load(open(os.path.join(self.site, "badges", "bench.json")))
        self.assertEqual(badge["message"], "accounting 3,731/s (github-ubuntu-24.04)")
        self.assertTrue(os.path.exists(os.path.join(self.site, "benchmarks", "runs", os.path.basename(FIXTURE))),
                        "the run is kept for the trend")

    def test_runs_accumulate_and_the_newest_dedicated_one_is_featured(self):
        self.build()
        run = json.load(open(FIXTURE))
        aws = copy.deepcopy(run)
        aws["environment"].update(where="aws-small", shared_host=False, date="2026-11-12T10:00:00+00:00")
        aws["workloads"]["accounting"].update(ceiling_rps=9000.0, load_limited=True)
        json.dump(aws, open(os.path.join(self.results, "bench-20261112T100000Z.json"), "w"))
        page = self.build()
        latest = json.load(open(os.path.join(self.site, "benchmarks", "latest.json")))
        self.assertEqual(latest["runs"], 2)
        self.assertEqual(latest["where"], "aws-small")
        badge = json.load(open(os.path.join(self.site, "badges", "bench.json")))
        self.assertEqual(badge["message"], "accounting ≥ 9,000/s (aws-small)")
        self.assertLess(page.index("aws-small"), page.index("github-ubuntu-24.04"), "dedicated machines first")

    def test_no_results_writes_nothing(self):
        os.remove(os.path.join(self.results, os.path.basename(FIXTURE)))
        self.assertIsNone(self.build())
        self.assertFalse(os.path.exists(os.path.join(self.site, "badges", "bench.json")))

    def test_a_broken_result_file_is_skipped(self):
        open(os.path.join(self.results, "bench-20261110T000000Z.json"), "w").write("{not json")
        self.build()
        latest = json.load(open(os.path.join(self.site, "benchmarks", "latest.json")))
        self.assertEqual(latest["runs"], 1)


if __name__ == "__main__":
    unittest.main()
