import unittest
import src.padding as padding
import src.aes as aes
import src.utils.filereader as filereader

from secrets import token_bytes
from src.oracle import EncryptionOracle
from src.AESModeDetector import AESModeDetector

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
        self.assertEqual(plaintext, padding.strip_pkcs7_pad(actual))
        
    def test_set3_challenge11(self):
        self.assertEqual('See tests/src/test_AESModeDetector.py', 'See tests/src/test_AESModeDetector.py')

    def test_set3_challenge12(self):
        secret_text = filereader.read_formatted_base64_file('./tests/fixtures/set_2_challenge_12.txt')
        detector = AESModeDetector()
        oracle = EncryptionOracle()
        detected_block_size = detector.detect_block_size(secret_text, oracle)
        self.assertEqual(16, detected_block_size)
        # I know I need at least 3 blocks to accurately detect a mode
        block = (b'\x00' * detected_block_size) * 3
        detected_mode = detector.detect_ecb_mode(oracle.encrypt(block + secret_text))
        self.assertEqual(True, detected_mode['ecb'])



        