import unittest
import src.utils.filereader as filereader

from src.RepeatingKeyDetector import RepeatingKeyDetector

class RepeatingKeyDetectorTest(unittest.TestCase):

    def test_detect_key_length(self):
        c_bytes = filereader.read_formatted_base64_file("./tests/fixtures/set_1_challenge_6.txt")
        key_detector = RepeatingKeyDetector(c_bytes)
        key_len_scores = key_detector.detect_key_length(2, 40)
        expected = 29
        actual = key_len_scores[0][0]
        self.assertEqual(expected, actual)