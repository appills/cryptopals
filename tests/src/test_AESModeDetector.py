import unittest

from secrets import token_bytes
from src.AESModeDetector import AESModeDetector
from src.oracle import EncryptionOracle

class AESModeDetectorTest(unittest.TestCase):
    
    def __init__(self, *args, **kwargs):
        super(AESModeDetectorTest, self).__init__(*args, **kwargs)
    
    def testAESModeDetector(self):
        # needs at least 3 repeated blocks to detect correctly?
        # update: duh its an oracle you're allowed to use chosen plaintext attacks
        plaintext = b'YELLOW SUBMARINE'*3
        oracle = EncryptionOracle()
        for i in range(0, 100):
            oracle.randomly_encrypt(plaintext)

        ciphertexts = oracle.get_ciphertexts()
        detector = AESModeDetector()
        for c in ciphertexts['ecb']:
            result = detector.detect_ecb_mode(c, 16)
            self.assertEqual(True, result['ecb'])
        
        for c in ciphertexts['cbc']:
            result = detector.detect_ecb_mode(c, 16)
            self.assertEqual(False, result['ecb'])