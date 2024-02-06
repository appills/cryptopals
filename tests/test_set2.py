import unittest
import src.padding as padding
import src.aes as aes
import src.utils.filereader as filereader

class Set2Test(unittest.TestCase):
    
    def __init__(self, *args, **kwargs):
        super(Set2Test, self).__init__(*args, **kwargs)

    def test_set2_challenge9(self):
        block = b'YELLOW SUBMARINE'
        expected = b'YELLOW SUBMARINE\x04\x04\x04\x04'
        self.assertEqual(expected, padding.pkcs7_pad(block, 20))

    def test_set2_challenge10(self):
        key = b"YELLOW SUBMARINE"
        iv = b'\x00'*16
        ciphertext = filereader.read_formatted_base64_file('./tests/fixtures/set_2_challenge_10.txt')
        actual = aes.cbc_mode_decrypt(key, ciphertext, iv)
        with open('./tests/fixtures/spoilers/set_2_challenge_10.decrypt', 'rb') as fh:
            plaintext = fh.read()
        self.assertEqual(plaintext, actual)
        