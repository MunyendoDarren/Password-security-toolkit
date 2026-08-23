"""
Basic unit tests for strength_checker.py.
Run with: python -m pytest tests/  (or: python -m unittest discover tests)
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from strength_checker import (  # noqa: E402
    calculate_entropy,
    has_sequential_chars,
    has_repeated_chars,
    has_keyboard_walk,
    is_common_password,
    score_password,
)


class TestEntropy(unittest.TestCase):
    def test_empty_password(self):
        self.assertEqual(calculate_entropy(""), 0.0)

    def test_lowercase_only(self):
        # pool=26, length=4 -> 4 * log2(26)
        entropy = calculate_entropy("abcd")
        self.assertAlmostEqual(entropy, 4 * 4.700439718, places=3)

    def test_all_classes_increases_entropy(self):
        simple = calculate_entropy("aaaaaaaa")
        complex_pw = calculate_entropy("aA1!aA1!")
        self.assertGreater(complex_pw, simple)


class TestPatternDetection(unittest.TestCase):
    def test_sequential_ascending(self):
        self.assertTrue(has_sequential_chars("xabc9"))

    def test_sequential_descending(self):
        self.assertTrue(has_sequential_chars("x321y"))

    def test_no_sequential(self):
        self.assertFalse(has_sequential_chars("xK9mQ2p"))

    def test_repeated_chars(self):
        self.assertTrue(has_repeated_chars("helllo"))

    def test_no_repeated_chars(self):
        self.assertFalse(has_repeated_chars("abcdef"))

    def test_keyboard_walk(self):
        self.assertTrue(has_keyboard_walk("myqwerty1"))

    def test_no_keyboard_walk(self):
        self.assertFalse(has_keyboard_walk("xK9mQ2vL7p"))


class TestCommonPasswordCheck(unittest.TestCase):
    def test_common_password_detected(self):
        common = {"password", "123456"}
        self.assertTrue(is_common_password("Password", common))  # case-insensitive

    def test_uncommon_password_not_flagged(self):
        common = {"password", "123456"}
        self.assertFalse(is_common_password("xK9mQ2vL7p", common))


class TestScoring(unittest.TestCase):
    def setUp(self):
        self.common = {"password", "123456", "qwerty"}

    def test_common_password_scores_low(self):
        result = score_password("password", self.common)
        self.assertLessEqual(result["score"], 10)
        self.assertEqual(result["rating"], "Very Weak")

    def test_strong_random_password_scores_high(self):
        result = score_password("xK9$mQ2#vL7pR4z!", self.common)
        self.assertGreaterEqual(result["score"], 65)
        self.assertIn(result["rating"], ("Strong", "Very Strong"))

    def test_empty_password_invalid(self):
        result = score_password("", self.common)
        self.assertEqual(result["rating"], "Invalid")

    def test_score_bounded_0_to_100(self):
        for pw in ["a", "aaaaaaaaaaaaaaaa", "password", "xK9$mQ2#vL7pR4z!Bw6&"]:
            result = score_password(pw, self.common)
            self.assertGreaterEqual(result["score"], 0)
            self.assertLessEqual(result["score"], 100)


if __name__ == "__main__":
    unittest.main()
