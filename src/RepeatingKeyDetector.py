import src.xor as xorcipher
from src.hamming import hamming_distance
from src.scoring import PlaintextScoreCalculator

class RepeatingKeyDetector:

    def __init__(self, c_buf: bytes):
        self.ciphertext = c_buf
        self.calculator = PlaintextScoreCalculator('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ.,\'"\n ')
        self.scores = []
        
    def print_iter(self, it):
        for i in it:
            print(i)

    def detect_key_length(self, min_len, max_len):
        c_len = len(self.ciphertext)
        scores = []
        for key_len in range(min_len, max_len):
            total_blocks = c_len / key_len
            num = 0
            sum_of_distances = 0
            for distance in self.gen_edit_distance(total_blocks, key_len):
                sum_of_distances += distance
                num += 1
            avg = sum_of_distances / num
            
            score = (key_len, avg)
            scores.append(score)
        scores.sort(key=lambda tup: tup[1])
        return scores
    
    def gen_edit_distance(self, total_blocks, key_len):
        num = 0
        while (num < total_blocks):
            first_block = self.ciphertext[num*key_len:(num+1)*key_len]
            second_block = self.ciphertext[(num+1)*key_len:(num+2)*key_len]
            edit_distance = hamming_distance(first_block, second_block) / key_len
            yield edit_distance
            num += 2
        
    def block_ciphertext_by_key_len(self, key_len):
        self.blocks = []
        text_len = len(self.ciphertext)
        prev = 0
        for i in range(0, text_len, key_len):
            self.blocks.append(self.ciphertext[prev:i])
            prev = i
    
    def transpose_blocks(self, key_len):
        self.transposed = [0]*key_len
        for i in range(0, key_len):
            self.transposed[i] = bytearray(key_len)
            
        for block in self.blocks:
            for i in range(0, len(block)):
                self.transposed[i].append(block[i])
        return self.transposed
    
    # todo this
    def single_byte_xor_per_block(self, key_len):
        k_buf = bytearray(key_len)
        # for each block
        i = 0
        for block in self.transposed:
            # bruteforce singlebyte xor
            xors = xorcipher.bruteforce_single_byte_xor(block)
            # get highest score
            scores = self.calculator.calculate_scores(xors)
            # highest score = byte for that position
            k_byte = scores[0][1]
            k_buf[i] = k_byte
            i+=1
        return k_buf
        
    def decrypt_ciphertext_with_kbuf(self, k_buf):
        return xorcipher.repeating_key_xor(k_buf, self.ciphertext)