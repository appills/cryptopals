import unittest
import src.utils.bytecodec as bytecodec

class ByteCodecTest(unittest.TestCase):

    def test_hex_to_bytes(self):
        data = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
        expected = b"I'm killing your brain like a poisonous mushroom"
        actual = bytecodec.hex_to_bytes(data)
        self.assertEqual(expected, actual)
        
    def test_bytes_to_hex(self):
        data = b"I'm killing your brain like a poisonous mushroom"
        expected = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
        actual = bytecodec.bytes_to_hex(data)
        self.assertEqual(expected, actual)

    def test_base64_to_bytes(self):
        data = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
        expected = b"I'm killing your brain like a poisonous mushroom"
        actual = bytecodec.base64_to_bytes(data)
        self.assertEqual(expected, actual)
        
    def test_bytes_to_base64(self):
        data = b"I'm killing your brain like a poisonous mushroom"
        expected = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
        actual = bytecodec.bytes_to_base64(data)
        self.assertEqual(expected, actual)