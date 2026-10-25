"""Regression: legal pages must be discovered from the homepage, not just fixed paths.

The gmedcrop.com false positive (24 Oct 2026): the site links its privacy policy at
/policies/privacy-policy (Shopify default), which the fixed path list did not include.
"""
from __future__ import annotations

import unittest

from shipproof import live


class CandidateLinkTests(unittest.TestCase):
    def test_shopify_privacy_link_is_discovered(self):
        html = '<a href="/policies/privacy-policy">Privacy</a><a href="/collections/all">Shop</a>'
        links = live._candidate_links("https://www.example-store.com", html, "privacy")
        self.assertEqual(links, ["https://www.example-store.com/policies/privacy-policy"])

    def test_terms_link_with_absolute_url(self):
        html = '<a href="https://www.example-store.com/policies/terms-of-service">Terms</a>'
        links = live._candidate_links("https://www.example-store.com", html, "terms")
        self.assertEqual(links, ["https://www.example-store.com/policies/terms-of-service"])

    def test_external_links_are_ignored(self):
        html = '<a href="https://other-site.com/privacy">Privacy</a>'
        self.assertEqual(live._candidate_links("https://www.example-store.com", html, "privacy"), [])

    def test_keyword_must_appear_in_url(self):
        html = '<a href="/about">About</a><a href="/contact">Contact</a>'
        self.assertEqual(live._candidate_links("https://example.com", html, "privacy"), [])

    def test_expanded_paths_cover_shopify(self):
        self.assertIn("/policies/privacy-policy", live.PRIVACY_PATHS)
        self.assertIn("/policies/terms-of-service", live.TERMS_PATHS)


if __name__ == "__main__":
    unittest.main()
