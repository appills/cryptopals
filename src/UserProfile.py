import src.aes as aes
import src.padding as padding
import src.utils.bytecodec as bytecodec

from secrets import token_bytes

def profile_for(email):
    uid = '10'
    role = 'user'
    email = sanitize_email(email)
    d = {
        'email': email,
        'uid': uid,
        'role': role
    }
    return dict_to_urlencode(d)

def urlencode_to_dict(s: str) -> dict:
    key_value_pairs = s.split('&')
    d = dict()
    for key_and_value in key_value_pairs:
        key_and_value = key_and_value.split('=')
        d[key_and_value[0]] = key_and_value[1]
    return d

def dict_to_urlencode(d: dict) -> str:
    enc = []
    for k,v in d.items():
        enc.append(k + '=' + v)
    return '&'.join(enc)

def sanitize_email(email):
    return email.replace('&', '').replace('=', '')

class UserProfile:
    def __init__(self, key: bytes):
        self.key = key

    def encrypted_profile_for(self, email):
        encoded = bytecodec.utf8_to_bytes(profile_for(email))
        padded_profile = padding.pkcs7_pad(encoded)
        return aes.ecb_mode_encrypt(self.key, padded_profile)
    
    def decrypt_profile(self, profile: bytes):
        decrypted = aes.ecb_mode_decrypt(self.key, profile)
        decoded = bytecodec.bytes_to_utf8(padding.strip_pkcs7_pad(decrypted))
        return urlencode_to_dict(decoded)