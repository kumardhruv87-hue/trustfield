"""OSV dependency checks: pure parsing, no network."""
from __future__ import annotations

import unittest

from shipproof import osv


class OsvTests(unittest.TestCase):
    def test_collect_maps_package_and_severity(self):
        results = [{"vulns": [
            {"id": "GHSA-aaaa", "summary": "Prototype pollution",
             "database_specific": {"severity": "HIGH"},
             "affected": [{"ranges": [{"events": [{"fixed": "4.17.21"}]}]}]},
            {"id": "CVE-2024-0001", "summary": "ReDoS",
             "database_specific": {"severity": "MODERATE"}},
        ]}]
        deps = [{"name": "lodash", "version": "4.17.20", "ecosystem": "npm"}]
        out = osv.collect(results, deps)
        self.assertEqual(len(out), 2)
        self.assertEqual(out[0]["package"], "lodash")
        self.assertEqual(out[0]["severity"], "high")
        self.assertEqual(out[0]["fixed"], "4.17.21")
        self.assertEqual(out[1]["severity"], "medium")

    def test_parse_requirements(self):
        text = "flask==2.0.1\nrequests>=2.31.0\n# comment\n-r base.txt\n"
        deps = osv.parse_requirements(text)
        self.assertIn({"name": "flask", "version": "2.0.1", "ecosystem": "PyPI"}, deps)
        self.assertIn({"name": "requests", "version": "2.31.0", "ecosystem": "PyPI"}, deps)
        self.assertEqual(len(deps), 2)

    def test_empty_query_is_safe(self):
        self.assertEqual(osv.query([]), [])
        self.assertEqual(osv.collect([], []), [])


if __name__ == "__main__":
    unittest.main()
