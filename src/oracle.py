import src.aes as aes
from secrets import token_bytes
from random import randrange
from src.padding import pkcs7_pad, strip_pkcs7_pad
from urllib.parse import quote_plus
from src.utils.bytecodec import utf8_to_bytes, bytes_to_utf8

def generate_key(size=16) -> bytes:
    return token_bytes(size)

def random_number() -> int:
    return int.from_bytes(token_bytes(1))

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
        self.random_prefix = token_bytes(random_number())
        self.init_vector = token_bytes(16)

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

    def randomly_prepend_and_encrypt(self, attacker_buf, secret_buf):
        # random prefix is per instance, not per invocation
        p_buf = b''.join([self.random_prefix, attacker_buf, secret_buf])
        padded_buf = pkcs7_pad(p_buf)
        return aes.ecb_mode_encrypt(self.key, padded_buf)
    
    def cbc_oracle_encrypt(self, user_input: str) -> bytes:
        prepend = "comment1=cooking%20MCs;userdata="
        append = ";comment2=%20like%20a%20pound%20of%20bacon"
        # todo quote out the ; and = characters
        message = self.encode_user_input(prepend, user_input, append)
        # pad to block length & encrypt under random key (and random IV)
        padded_message = pkcs7_pad(utf8_to_bytes(message))
        c_buf = aes.cbc_mode_encrypt(self.key, padded_message, self.init_vector)
        return c_buf
    
    def cbc_oracle_decrypt(self, c_buf) -> bytes:
        p_buf = aes.cbc_mode_decrypt(self.key, c_buf, self.init_vector)
        p_buf = strip_pkcs7_pad(p_buf)
        return p_buf
    
    def encode_user_input(self, prepend, user_input, append):
        return prepend + quote_plus(user_input) + append
    
    def parse_encoded_message(self, message: str) -> list:
        tuples = []
        key_value_pairs = message.split(';')
        for pairs in key_value_pairs:
            key_and_value = pairs.split('=')
            tuples.append((key_and_value[0], key_and_value[1]))
        return tuples
    
    def find_admin_tuple(self, tups):
        for tup in tups:
            if tup[0] == 'admin':
                return tup
        return ()

    def get_ciphertexts(self):
        return self.ciphertexts
    
    