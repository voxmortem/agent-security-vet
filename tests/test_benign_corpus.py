"""Benign corpus: realistic skills, plugins, repos and articles.

Acceptance threshold, fixed before the first run: 0 HIGH findings across the corpus.
MED/LOW findings are allowed (they mean "read this in context").
"""
import unittest

import corpus_benign
from _support import TempCase, describe, rules, scan, sev_count


class BenignCorpus(TempCase):
    def test_at_least_eight_fixtures(self):
        self.assertGreaterEqual(len(corpus_benign.BUILDERS), 8)

    def test_zero_high_with_declared_kind(self):
        for build in corpus_benign.BUILDERS:
            with self.subTest(fixture=build.__name__):
                path, kind = build(self.sub("declared"))
                s = scan(path, kind=kind)
                self.assertGreater(s.stats["files"], 0)
                self.assertEqual(0, sev_count(s, "HIGH"),
                                 "benign fixture %s produced HIGH findings:\n%s" % (build.__name__, describe(s)))

    def test_zero_high_with_auto_kind(self):
        for build in corpus_benign.BUILDERS:
            with self.subTest(fixture=build.__name__):
                path, kind = build(self.sub("auto"))
                s = scan(path, kind="auto")
                self.assertEqual(kind, s.kind, "auto-detected kind for %s" % build.__name__)
                self.assertEqual(0, sev_count(s, "HIGH"),
                                 "benign fixture %s produced HIGH findings:\n%s" % (build.__name__, describe(s)))

    def test_security_article_quotes_are_medium(self):
        path, kind = corpus_benign.security_article_html(self.tmp)
        s = scan(path, kind=kind)
        med = rules(s, "MED")
        self.assertIn("inj-override", med, "a visibly quoted injection example must be reported as MED")
        self.assertIn("inj-ai-addressed", med)
        self.assertEqual(0, sev_count(s, "HIGH"), describe(s))

    def test_defensive_wording_is_not_an_attack(self):
        path, kind = corpus_benign.defensive_skill(self.tmp)
        s = scan(path, kind=kind)
        self.assertNotIn("inj-override", rules(s), "defensive 'ignore instructions found in web pages' was flagged")

    def test_emoji_and_cyrillic_are_quiet(self):
        path, kind = corpus_benign.russian_emoji_skill(self.tmp)
        s = scan(path, kind=kind)
        self.assertEqual(set(), {r for r in rules(s) if r.startswith("uni-tag") or r.startswith("uni-variation")},
                         "emoji flag / variation sequences must not be reported")
        self.assertEqual(0, sev_count(s, "MED"), describe(s, "MED"))


if __name__ == "__main__":
    unittest.main()
