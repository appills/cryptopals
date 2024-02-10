import unittest

from secrets import token_bytes
from src.AESModeDetector import AESModeDetector
from src.oracle import EncryptionOracle

class AESModeDetectorTest(unittest.TestCase):
    
    def __init__(self, *args, **kwargs):
        super(AESModeDetectorTest, self).__init__(*args, **kwargs)
    
    def testAESModeDetector(self):
        key = token_bytes(16)
        # needs at least 3 repeated blocks to detect correctly?
        plaintext = b'YELLOW SUBMARINE'*3
        oracle = EncryptionOracle(key)
        for i in range(0, 100):
            oracle.encrypt(plaintext)

        ciphertexts = oracle.get_ciphertexts()
        detector = AESModeDetector()
        for c in ciphertexts['ecb']:
            result = detector.detect_ecb_mode(c, 16)
            self.assertEqual(True, result['ecb'])
        
        for c in ciphertexts['cbc']:
            result = detector.detect_ecb_mode(c, 16)
            self.assertEqual(False, result['ecb'])