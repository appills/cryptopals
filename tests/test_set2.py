import unittest
import src.padding as padding
import src.aes as aes
import src.utils.filereader as filereader
import src.utils.bytecodec as bytecodec

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
        
    def test_set2_challenge11(self):
        self.assertEqual('See ./tests/src/test_AESModeDetector.py', 'See ./tests/src/test_AESModeDetector.py')

    def test_set2_challenge12(self):
        expected = filereader.read_formatted_base64_file('./tests/fixtures/set_2_challenge_12.txt')
        secret_text = expected
        detector = AESModeDetector()
        oracle = EncryptionOracle()
        detected_block_size = detector.detect_block_size(secret_text, oracle)
        self.assertEqual(16, detected_block_size)
        # I know I need at least 3 blocks to accurately detect a mode
        block = (b'\x00' * detected_block_size) * 3
        detected_mode = detector.detect_ecb_mode(oracle.encrypt(block + secret_text))
        self.assertEqual(True, detected_mode['ecb'])
        # Q: Think about what the oracle function is going to put in that last byte position.
        one_byte_short = b'\x00'*(detected_block_size-1)
        ''' 
        A: it should put the first byte of the first block in there
        we are taking one byte from the front of the secret_text and adding it to our chosen block (in parentheses below)
        e.g. [0 0 0 0 0 0 0 0 0 0 0 0 0 0 0] + [(?) ? ? ? ? ? ? ? ? ? ? ? ? ? ? ? ...]
        create a dict of every possible last byte where the keys are the ciphertext and the vals are the last byte
        e.g. [0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 1] ... [0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 255]
        encrypt (one_byte_short + secret_text) and take the first block: [0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 ?]
        check the ciphertext dictionary for a match for first_block
        remove that first byte from the secret_text and do the process all over
        '''
        ciphertext_dict = dict()
        for i in range(0,255):
            ciphertext_dict[oracle.encrypt(one_byte_short + i.to_bytes())] = i

        plaintext_bytes = []
        while len(secret_text) > 0:
            c_buf = oracle.encrypt(one_byte_short + secret_text)
            plaintext_bytes.append(ciphertext_dict[c_buf[0:16]])
            secret_text = secret_text[1:]
        plaintext = b''.join([i.to_bytes() for i in plaintext_bytes])
        self.assertEqual(expected, plaintext) # cool af








        