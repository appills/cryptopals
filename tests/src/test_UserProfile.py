import unittest
import src.utils.bytecodec as bytecodec

from secrets import token_bytes
from src.UserProfile import urlencode_to_dict, profile_for, UserProfile
from src.padding import pkcs7_pad
from src.utils.bytecodec import utf8_to_bytes, bytes_to_utf8

class UserProfileTest(unittest.TestCase):

    def test_urlencode_to_dict(self):
        expected = {
            'foo': 'bar',
            'baz': 'qux',
            'zap': 'zazzle'
        }
        actual = urlencode_to_dict('foo=bar&baz=qux&zap=zazzle')
        self.assertEqual(expected, actual)

    def test_profile_for(self):
        expected = 'email=foo@bar.com&uid=10&role=user'
        actual = profile_for('foo@bar.com')
        self.assertEqual(expected, actual)
        expected = 'email=foo@bar.comroleadmin&uid=10&role=user'
        actual = profile_for('foo@bar.com&role=admin')
        self.assertEqual(expected, actual)
    
    def test_encrypted_profile(self):
        key = self.get_static_key()
        profile = UserProfile(key)
        encrypted = profile.encrypted_profile_for('foo@bar.com')
        decrypted = profile.decrypt_profile(encrypted)
        expected = {
            'email': 'foo@bar.com',
            'uid': '10',
            'role': 'user'
        }
        self.assertEqual(expected, decrypted)

    def test_attack_profile(self):
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

    def get_static_key(self):
        with open('./tests/fixtures/set_2_challenge13.key', 'r') as fh:
            hex_key = fh.read()
        key = bytecodec.hex_to_bytes(hex_key)
        return key