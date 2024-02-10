import unittest
import src.aes as aes
from src.padding import pkcs7_pad, strip_pkcs7_pad

class AESTest(unittest.TestCase):
    def __init__(self, *args, **kwargs):
        super(AESTest, self).__init__(*args, **kwargs)

    def test_ecb_mode(self):
        key = b"YELLOW SUBMARINE"
        plaintext = b"They say my lip gloss is poppin'"

        c_buf = aes.ecb_mode_encrypt(key, pkcs7_pad(plaintext))
        p_buf = aes.ecb_mode_decrypt(key, c_buf)
        self.assertEqual(plaintext, p_buf)

        plaintext = b"They say my lip gloss is poppin', my lip gloss is cool"
        padded_plaintext = pkcs7_pad(plaintext)
        c_buf = aes.ecb_mode_encrypt(key, padded_plaintext)
        p_buf = aes.ecb_mode_decrypt(key, c_buf)
        self.assertEqual(padded_plaintext, p_buf)
        self.assertEqual(plaintext, strip_pkcs7_pad(p_buf))

    def test_cbc_mode(self):
        key = b"YELLOW SUBMARINE"
        iv = b'\x00'*16
        plaintext = b"They say my lip gloss is poppin'"
        c_buf = aes.cbc_mode_encrypt(key, pkcs7_pad(plaintext), iv)
        p_buf = aes.cbc_mode_decrypt(key, c_buf, iv)
        self.assertEqual(plaintext, strip_pkcs7_pad(p_buf))

        plaintext = b"They say my lip gloss is poppin', my lip gloss is cool"
        padded_plaintext = pkcs7_pad(plaintext)
        self.assertNotEqual(plaintext, padded_plaintext) # sanity test
        c_buf = aes.cbc_mode_encrypt(key, pkcs7_pad(plaintext), iv)
        p_buf = aes.cbc_mode_decrypt(key, c_buf, iv)
        self.assertEqual(padded_plaintext, p_buf) # sanity test
        self.assertEqual(plaintext, strip_pkcs7_pad(p_buf))