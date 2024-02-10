import unittest
import src.oracle as oracle

class OracleTest(unittest.TestCase):
    
    def __init__(self, *args, **kwargs):
        super(OracleTest, self).__init__(*args, **kwargs)

    def test_random_encryption_oracle(self):
        p_buf = b'high heels on my tippies'
        for i in range(0, 100):
            oracle.random_encryption_oracle(p_buf)
        self.assertEqual(1, 1)