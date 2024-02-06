import unittest
from src.hamming import hamming_distance

class HammingDistanceTest(unittest.TestCase):

    def __init__(self, *args, **kwargs):
        super(HammingDistanceTest, self).__init__(*args, **kwargs)
    
    def test_edit_distance(self):
        expected = 37
        p = b'this is a test'
        q = b'wokka wokka!!!'
        actual = hamming_distance(p, q)
        self.assertEqual(expected, actual)
        
    def test_edit_distance(self):    
        expected = 39
        p = b'this is a test'
        q = b'wokka wokka!!!!'
        actual = hamming_distance(p, q)
        self.assertEqual(expected, actual)