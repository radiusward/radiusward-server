# Copyright 2026 The radiusward Authors
# SPDX-License-Identifier: Apache-2.0
"""The BOM lists exactly the published modules: every module of the build that is deployed, nothing else."""

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def artifact_id(pom: str) -> str:
    """The module's own artifactId: the first one after its parent block."""
    rest = pom.split("</parent>", 1)[-1]
    return re.search(r"<artifactId>([^<]+)</artifactId>", rest).group(1)


class BomTest(unittest.TestCase):

    def test_the_bom_lists_every_published_module(self):
        root = (ROOT / "pom.xml").read_text()
        modules = re.findall(r"<module>([^<]+)</module>", root.split("<profiles>", 1)[0])
        published = set()
        for module in modules:
            pom = (ROOT / module / "pom.xml").read_text()
            if module == "bom" or "<maven.deploy.skip>true</maven.deploy.skip>" in pom:
                continue
            published.add(artifact_id(pom))
        bom = (ROOT / "bom" / "pom.xml").read_text()
        listed = set(re.findall(r"<artifactId>(radiusward-[^<]+)</artifactId>", bom)) - {"radiusward-bom"}
        self.assertEqual(published, listed, "bom/pom.xml must list exactly the published modules")
        self.assertGreater(len(listed), 20)

    def test_the_bom_declares_the_parents_formatter_version(self):
        root = (ROOT / "pom.xml").read_text()
        bom = (ROOT / "bom" / "pom.xml").read_text()
        version = re.search(r"<spotless.version>([^<]+)</spotless.version>", root).group(1)
        declared = re.search(r"<artifactId>spotless-maven-plugin</artifactId>\s*<version>([^<]+)</version>", bom)
        self.assertIsNotNone(declared, "bom/pom.xml declares spotless-maven-plugin for ./mvnw spotless:apply")
        self.assertEqual(version, declared.group(1))


if __name__ == "__main__":
    unittest.main()
