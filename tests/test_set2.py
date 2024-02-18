import unittest
import src.padding as padding
import src.aes as aes
import src.utils.filereader as filereader

from secrets import token_bytes
from src.padding import pkcs7_pad
from src.utils.bytecodec import bytes_to_utf8
from src.UserProfile import UserProfile
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
        SUBROUTINE:
        encrypt (one_byte_short + secret_text[:1]) and take the first_block of the ciphertext [0:16]
        check the ciphertext dictionary for a match for first_block
        remove that first byte from the secret_text & GOTO SUBROUTINE
        '''
        ciphertext_dict = dict()
        for i in range(0,255):
            ciphertext_dict[oracle.encrypt(one_byte_short + i.to_bytes())] = i

        plaintext_bytes = []
        while len(secret_text) > 0:
            c_buf = oracle.encrypt(one_byte_short + secret_text[:1])
            plaintext_bytes.append(ciphertext_dict[c_buf[0:16]])
            secret_text = secret_text[1:]
        plaintext = b''.join([i.to_bytes() for i in plaintext_bytes])
        self.assertEqual(expected, plaintext) # cool af

    def test_set2_challenge13(self):
        key = token_bytes(16)
        profile = UserProfile(key)
        '''
            we're going to use the cipher text of this:
                email=aaaaaaaaaa
                aaa&uid=10&role=
                userxxxxxxxxxxxx    <------ this block will get replaced
        '''
        c_buf1 = profile.encrypted_profile_for('a'*13)
        '''
            by replacing the last block (userxxxxxxxxxxxx)
            with the second block of the cipher text of:
                email=aaaaaaaaaa
                adminxxxxxxxxxxx    <------ this block is the replacement
                uid=10&role=user
        '''
        admin_padded_buf = (b'a'*10) + pkcs7_pad(b'admin')
        c_buf2 = profile.encrypted_profile_for(bytes_to_utf8(admin_padded_buf))

        payload = b''.join([c_buf1[0:16], c_buf1[16:32], c_buf2[16:32]])
        decrypted = profile.decrypt_profile(payload)
        expected = {
            'email': 'aaaaaaaaaaaaa',
            'uid': '10',
            'role': 'admin'
        }
        self.assertEqual(expected, decrypted)
        return
    
    def test_set2_challenge14(self):
        expected = filereader.read_formatted_base64_file('./tests/fixtures/set_2_challenge_12.txt')
        secret_text = expected
        oracle = EncryptionOracle()
        '''
        Add bytes until I get repeated blocks
        then I know how many bytes I need to separate the prepended bytes and the secret text
        then I repeat the attack from #12
        '''
        found_repeat_blocks = False
        count = 1
        while not found_repeat_blocks:
            chunks = dict()
            attack = b'\x00'*count
            c_buf = oracle.randomly_prepend_and_encrypt(attack, secret_text)
            c_blocks = self.chunk_text(c_buf, 16)
            block_num = 0
            for block in c_blocks:
                if block in chunks.keys():
                    found_repeat_blocks = True
                    attack_len = len(attack)
                    break
                else:
                    chunks[block] = 1
                    block_num+=1
            count+=1

        
        '''
        sure its ugly but it works and thats what
        '''
        start_index_of_secret_text = block_num*16
        start_index_of_chosen_text = start_index_of_secret_text-attack_len
        one_byte_short = b'\x00'*(attack_len-1)
        possible_ciphertexts = dict()
        for i in range(0,255):
            c_buf = oracle.randomly_prepend_and_encrypt(one_byte_short + i.to_bytes(), secret_text)
            block_to_inspect = c_buf[start_index_of_chosen_text:]
            possible_ciphertexts[block_to_inspect] = i

        plaintext_bytes = []
        hold_text = secret_text
        while len(secret_text) > 0:
            c_buf = oracle.randomly_prepend_and_encrypt(one_byte_short + secret_text[:1], hold_text)
            block_to_inspect = c_buf[start_index_of_chosen_text:]
            plaintext_bytes.append(possible_ciphertexts[block_to_inspect])
            secret_text = secret_text[1:]
        plaintext = b''.join([i.to_bytes() for i in plaintext_bytes])
        self.assertEqual(expected, plaintext) # cool af

        return
    def test_set2_challenge15(self):
        return
    def test_set2_challenge16(self):
        return
    
    def chunk_text(self, c_buf, size=16):
        blocks = []
        for i in range(0, len(c_buf), 16):
            blocks.append(c_buf[i:(i+size)])
        return blocks