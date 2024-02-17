import unittest
import src.utils.bytecodec as bytecodec

from secrets import token_bytes
from src.UserProfile import urlencode_to_dict, profile_for, UserProfile

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
    
    def test_attack_profile(self):
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
        '''
        email=fooooooooo
        @bar.commmmmmmmm
        &uid=10&role=use
        r
        '''

    def get_static_key(self):
        with open('./tests/fixtures/set_2_challenge13.key', 'r') as fh:
            hex_key = fh.read()
        key = bytecodec.hex_to_bytes(hex_key)
        return key