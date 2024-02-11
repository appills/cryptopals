import src.aes as aes
from secrets import token_bytes
from random import randrange
from src.padding import pkcs7_pad

def generate_key(size=16) -> bytes:
    return token_bytes(size)

def random_encryption_oracle(plaintext: bytes):
    key = generate_key(16)
    # pretty sure exclusive
    plaintext = pkcs7_pad(token_bytes(randrange(5, 11)) + plaintext + token_bytes(randrange(5, 11)))
    if randrange(0, 2) & 1:
        return aes.ecb_mode_encrypt(key, plaintext)
    return aes.cbc_mode_encrypt(key, plaintext, token_bytes(16))

class EncryptionOracle:
    '''
        for testing
        we should be able to detect ecb on all self.ciphertexts['ecb']
        and fail to detect ecb on all self.ciphertexts['cbc']
    '''
    def __init__(self):
        self.key = generate_key(16)

    def encrypt(self, plaintext):
        # pretty sure exclusive
        plaintext = pkcs7_pad(plaintext)
        c_buf = aes.ecb_mode_encrypt(self.key, plaintext)
        return c_buf
    
    def randomly_encrypt(self, plaintext):
        self.ciphertexts = {
            'ecb': [],
            'cbc': []
        }
        key = generate_key(16)
        # pretty sure exclusive
        plaintext = pkcs7_pad(token_bytes(randrange(5, 11)) + plaintext + token_bytes(randrange(5, 11)))
        if randrange(0, 2) & 1:
            c_buf = aes.ecb_mode_encrypt(key, plaintext)
            self.ciphertexts['ecb'].append(c_buf)
        else:
            c_buf = aes.cbc_mode_encrypt(key, plaintext, token_bytes(16))
            self.ciphertexts['cbc'].append(c_buf)
        return c_buf

    def get_ciphertexts(self):
        return self.ciphertexts
    
    