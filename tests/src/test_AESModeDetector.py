import unittest

from src.utils.filereader import read_formatted_base64_file
from src.AESModeDetector import AESModeDetector
from src.oracle import EncryptionOracle

class AESModeDetectorTest(unittest.TestCase):
    
    def __init__(self, *args, **kwargs):
        super(AESModeDetectorTest, self).__init__(*args, **kwargs)
        self.detector = AESModeDetector()
    
    def test_detect_ecb_mode(self):
        # needs at least 3 repeated blocks to detect correctly?
        # update: duh its an oracle you're allowed to use chosen plaintext attacks
        plaintext = b'YELLOW SUBMARINE'*3
        oracle = EncryptionOracle()
        for i in range(0, 100):
            oracle.randomly_encrypt(plaintext)

        ciphertexts = oracle.get_ciphertexts()
        for c in ciphertexts['ecb']:
            result = self.detector.detect_ecb_mode(c, 16)
            self.assertEqual(True, result['ecb'])
        
        for c in ciphertexts['cbc']:
            result = self.detector.detect_ecb_mode(c, 16)
            self.assertEqual(False, result['ecb'])
    
    def test_detect_block_size(self):
        secret_string = read_formatted_base64_file('./tests/fixtures/set_2_challenge_12.txt')
        actual = self.detector.detect_block_size(secret_string, EncryptionOracle())
        self.assertEqual(16, actual)