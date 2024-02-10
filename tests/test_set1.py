import unittest
import src.aes as aes
import src.xor as xorcipher
import src.utils.bytecodec as bytecodec
import src.utils.filereader as filereader

from src.scoring import PlaintextScoreCalculator
from src.RepeatingKeyDetector import RepeatingKeyDetector
from src.AESModeDetector import AESModeDetector

# bytes are readonly, bytearrays are read-write.
class Set1Test(unittest.TestCase):
    
    def __init__(self, *args, **kwargs):
        super(Set1Test, self).__init__(*args, **kwargs)
        
    # hex to base64
    def test_set1_challenge1(self):
        data = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
        expected = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
        hex_bytes = bytecodec.hex_to_bytes(data)
        actual = bytecodec.bytes_to_base64(hex_bytes)
        self.assertIsInstance(actual, str)
        self.assertEqual(expected, actual)
    
    # XOR two strings
    def test_set1_challenge2(self):
        first = bytecodec.hex_to_bytes('1c0111001f010100061a024b53535009181c')
        second = bytecodec.hex_to_bytes('686974207468652062756c6c277320657965')
        expected = '746865206b696420646f6e277420706c6179'
        
        actual_bytes = xorcipher.array_xor(first, second)
        actual = bytecodec.bytes_to_hex(actual_bytes)
        self.assertEqual(expected, actual)

    # break single-byte xor
    def test_set1_challenge3(self):
        expected = 88
        ciphertext = '1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736'
        plaintexts = xorcipher.bruteforce_single_byte_xor(bytecodec.hex_to_bytes(ciphertext))
        score_calculator = PlaintextScoreCalculator('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ.,\'" ')
        scores = score_calculator.calculate_scores(plaintexts)
        # check the byte of the highest entry
        self.assertEqual(expected, scores[0][1])

    def test_set1_challenge4(self):
        expected = 53
        # TODO rectify file path for fixtures/*.txt
        # i'm expecting a venv ran from the cryptopals root dir (cryptopals/*)
        with open("./tests/fixtures/set_1_challenge_4.txt") as fh:
            lines = fh.readlines()

        # different character set because of \n used in plaintext - yes, I'm cheating
        score_calculator = PlaintextScoreCalculator('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ.,\'"\n ')
        # TODO for each line, we compute all 255 single-byte XORs so maybe multithread
        for line in lines:
            decoded_line = bytecodec.hex_to_bytes(line)
            line_plaintexts = xorcipher.bruteforce_single_byte_xor(decoded_line)
            line_scores = score_calculator.calculate_scores(line_plaintexts)
            # check highest score to a threshold of .95
            if line_scores[0][0] > 0.95:
                actual = line_scores[0][1]
                break
        self.assertEqual(expected, actual)

    def test_set1_challenge5(self):
        expected = '0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f'
        key = bytearray('ICE', 'ascii')
        with open("./tests/fixtures/set_1_challenge_5.txt", 'rb') as fh:
            plaintext = fh.read()
        c_buf = xorcipher.repeating_key_xor(key, plaintext)
        self.assertEqual(c_buf.hex(), expected)

    def test_set1_challenge6(self):
        c_bytes = filereader.read_formatted_base64_file("./tests/fixtures/set_1_challenge_6.txt")
        key_detector = RepeatingKeyDetector(c_bytes)
        # type: tuple
        key_len_scores = key_detector.detect_key_length(2, 40)
        key_len = key_len_scores[0][0]
        
        key_detector.block_ciphertext_by_key_len(key_len)
        transposed = key_detector.transpose_blocks(key_len)
        k_buf = key_detector.single_byte_xor_per_block(key_len)
        with open("./tests/fixtures/spoilers/set_1_challenge_6.key", 'rb') as fh:
            expected = fh.read()
        self.assertEqual(expected, k_buf)
        
        p_buf = key_detector.decrypt_ciphertext_with_kbuf(k_buf)
        with open("./tests/fixtures/spoilers/set_1_challenge_6.decrypt", 'rb') as fh:
            expected = fh.read()
        self.assertEqual(expected, p_buf)
        
    def test_set1_challenge7(self):
        k_buf = b'YELLOW SUBMARINE'
        c_bytes = filereader.read_formatted_base64_file("./tests/fixtures/set_1_challenge_7.txt")

        actual = aes.ecb_mode_decrypt(k_buf, c_bytes)
        
        with open("./tests/fixtures/spoilers/set_1_challenge_7.decrypt", 'rb') as fh:
            expected=fh.read()
        self.assertEqual(expected,actual)
        
    # TODO finish assertion
    def test_set1_challenge8(self):
        byte_blocks = []
        with open("./tests/fixtures/set_1_challenge_8.txt", 'r') as fh:
            byte_blocks = [line.strip() for line in fh]
        block_guess = 0
        detector = AESModeDetector()
        for c_buf in byte_blocks:
            block_guess+=1
            # chunk into blocks of 16
            # check if any of the blocks in ten_blocks collide with each other
            result = detector.detect_ecb_mode(c_buf, 32)
            if result['ecb'] == True:
                detected = block_guess
                actual = result
        
        # block 133
        self.assertEqual(133, detected)
        self.assertEqual('08649af70dc06f4fd5d2d69c744cd283', actual['block'])
        self.assertEqual(4, actual['frequency'])