import unittest
import src.padding as padding

class PaddingTest(unittest.TestCase):
    def testPKCS7(self):
        block = b'a' * 15
        expected = block+b'\x01'
        self.assertEqual(expected, padding.pkcs7_pad(block))

        block = b'a'
        expected = block+(b'\x0f'*15)
        self.assertEqual(expected, padding.pkcs7_pad(block))

        block = b'a'*16
        self.assertEqual(block, padding.pkcs7_pad(block))