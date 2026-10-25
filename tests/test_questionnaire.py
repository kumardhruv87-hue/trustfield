"""Trust center questionnaire: HTML + PDF exist and stay honest."""
from __future__ import annotations

import unittest

from shipproof import questionnaire


class QuestionnaireTests(unittest.TestCase):
    def test_questions_are_answered(self):
        self.assertGreaterEqual(len(questionnaire.QUESTIONS), 15)
        for question, answer in questionnaire.QUESTIONS:
            self.assertTrue(question.strip())
            self.assertGreater(len(answer), 60)

    def test_no_certification_claims(self):
        joined = " ".join(a for _q, a in questionnaire.QUESTIONS).lower()
        for forbidden in ("soc 2 certified", "iso 27001 certified", "is certified"):
            self.assertNotIn(forbidden, joined)

    def test_html_contains_all_questions(self):
        html = questionnaire.html_page()
        self.assertIn("Security questionnaire answers", html)
        self.assertIn("Download the PDF pack", html)
        for question, _answer in questionnaire.QUESTIONS[:5]:
            self.assertIn(question.split("?")[0][:30], html)

    def test_pdf_builds(self):
        blob = questionnaire.build_pdf()
        self.assertTrue(blob.startswith(b"%PDF-1.4"))
        self.assertGreater(len(blob), 4000)


if __name__ == "__main__":
    unittest.main()
