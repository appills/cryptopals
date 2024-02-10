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