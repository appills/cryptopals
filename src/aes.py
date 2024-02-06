import src.padding as padding
import src.xor as xorcipher
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

'''
    Wrapper for the cryptography import
    cipher.encryptor()
        encryptor.update() + encryptor.finalize()
    cipher.decryptor()
        decryptor.update() + decryptor.finalize()
'''
def ecb_mode_encrypt(key, p_buf) -> bytes:
    cipher = Cipher(algorithms.AES(key), modes.ECB())
    e = cipher.encryptor()
    return e.update(p_buf) + e.finalize()

def ecb_mode_decrypt(key, c_buf) -> bytes:
    cipher = Cipher(algorithms.AES(key), modes.ECB())
    d = cipher.decryptor()
    return d.update(c_buf) + d.finalize()

def cbc_mode_encrypt(key: bytes, p_buf: bytes, iv: bytes):
    p_buf = padding.pkcs7_pad(p_buf)
    num_blocks = int(len(p_buf) / 16)
    c_blocks = [bytearray(16)]*num_blocks # will yield this many ciphertext blocks
    for i in range(0, num_blocks):
        p = p_buf[i*16:(i+1)*16] # grab plaintext
        p = xorcipher.array_xor(iv, p) # xor with IV
        c = ecb_mode_encrypt(key, p) # encrypt in ecb
        iv = c # update iv
        c_blocks[i] = c
    return combine_blocks(c_blocks)

def cbc_mode_decrypt(key: bytes, c_buf: bytes, iv: bytes):
    num_blocks = int(len(c_buf) / 16)
    p_blocks = [bytearray(16)]*num_blocks
    for i in range(0, num_blocks):
        c = c_buf[i*16:(i+1)*16] # this is also the IV for the next block
        dec_c = ecb_mode_decrypt(key, c) # decrypt the block
        p_blocks[i] = xorcipher.array_xor(iv, dec_c) # xor with the IV
        iv = c # update for next iv
    
    # check if the last block is padded
    last_block = p_blocks[-1]
    # check it
    p_blocks[-1] = padding.strip_pkcs7_pad(last_block)
    return combine_blocks(p_blocks)

def combine_blocks(blocks):
    buf = b''
    for block in blocks:
        buf += block
    return buf