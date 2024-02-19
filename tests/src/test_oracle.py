import unittest
import src.oracle as oracle
from src.utils.bytecodec import utf8_to_bytes, bytes_to_utf8

class OracleTest(unittest.TestCase):
    
    def __init__(self, *args, **kwargs):
        super(OracleTest, self).__init__(*args, **kwargs)
        self.encryption_oracle = oracle.EncryptionOracle()

    def test_random_encryption_oracle(self):
        p_buf = b'high heels on my tippies'
        for i in range(0, 100):
            oracle.random_encryption_oracle(p_buf)
        self.assertEqual(1, 1)

    def test_encode_user_input(self):
        expected = 'comment1=cooking%20MCs;userdata=%3Badmin%3Dtrue%3B;comment2=%20like%20a%20pound%20of%20bacon'
        actual = self.encryption_oracle.encode_user_input("comment1=cooking%20MCs;userdata=", ";admin=true;", ";comment2=%20like%20a%20pound%20of%20bacon")
        self.assertEqual(expected, actual)
        
    def test_parse_encoded_message(self):
        data = 'comment1=cooking%20MCs;userdata=%3Badmin%3Dtrue%3B;comment2=%20like%20a%20pound%20of%20bacon'
        parsed = self.encryption_oracle.parse_encoded_message(data)
        acceptable = ['comment1', 'userdata', 'comment2']
        unacceptable = ['admin']
        for i in parsed:
            self.assertEqual(True, (i[0] in acceptable))
            self.assertEqual(False, (i[0] in unacceptable))

    def test_cbc_oracle(self):
        c_buf = self.encryption_oracle.cbc_oracle_encrypt(';admin=true;')
        parsed_message = self.encryption_oracle.parse_encoded_message(
            bytes_to_utf8(self.encryption_oracle.cbc_oracle_decrypt(c_buf))
            )
        acceptable = ['comment1', 'userdata', 'comment2']
        unacceptable = ['admin']
        for i in parsed_message:
            self.assertEqual(True, (i[0] in acceptable))
            self.assertEqual(False, (i[0] in unacceptable))

    def test_cbc_bit_flip(self):
        '''
        comment1=cooking
        %20MCs;userdata=	fill a block
        %3Badmin%3Dtrue%
        3B;comment2=%20l
        ike%20a%20pound%
        20of%20bacon4444
        '''
        control_block = 'a'*16
        user_input = ';admin=true;'
        '''
        comment1=cooking
        %20MCs;userdata=	fill a block
        0000000000000000    <--- control block, flip a byte here 
        %3Badmin%3Dtrue%    <--- one byte should flip
        3B;comment2=%20l 
        ike%20a%20pound%
        20of%20bacon4444
        '''
        '''
        my hurdles:
        I need exactly ;admin=true; so i need to flip 
        %3Badmin%3Dtrue% to
        xxxx;admin=true;
        so flip the last 12 bytes
        xxxx567890123456 
        '''
        c_buf = self.encryption_oracle.cbc_oracle_encrypt(control_block + user_input)
        # don't worry about the first 4 bytes
        c_blocks = self.chunk_text(c_buf)
        # grab the third block
        block = c_blocks[2]
        fun_block = self.get_mutable_block(block)
        # goal is to now find bytes which result in the desired flip
        desired = [i for i in ';admin=true;']
        best_block = [fun_block[i] for i in range(0, 4)]
        ith_position = 4
        while len(desired) > 0:
            # pop from the head
            char = desired.pop(0)
            best_block.append(
                self.get_desired_byte_for_character_at_pos(char, ith_position, fun_block, c_blocks)
            )
            ith_position+=1
        # now pop it in there
        best_block = [i.to_bytes() for i in best_block]
        best_block = self.build_from_chunks(best_block)
        c_blocks[2] = best_block
        c_buf = self.build_from_chunks(c_blocks)
        decrypted = self.encryption_oracle.cbc_oracle_decrypt(c_buf)
        mangled = bytes_to_utf8(decrypted)
        parsed = self.encryption_oracle.parse_encoded_message(mangled)
        admin_found = False
        for i in parsed:
            if i[0] == 'admin' and i[1] == 'true':
                admin_found = True
        self.assertEqual(True, admin_found)                

    def get_desired_byte_for_character_at_pos(self, char, at_pos, fun_block, c_blocks) ->int:
        for i in range(1, 255):
                bl = fun_block[0:4] + (i.to_bytes())*12
                # at the at_pos position, look for char
                c_blocks[2] = bl
                flipped_c_buf = self.build_from_chunks(c_blocks)
                decrypted = self.encryption_oracle.cbc_oracle_decrypt(flipped_c_buf)
                # chunk again, 4th block of plain, check at_pos index
                flipped_blocks = self.chunk_text(decrypted)
                if (flipped_blocks[3][at_pos] == ord(char)):
                    return i

    def chunk_text(self, c_buf, size=16):
        blocks = []
        for i in range(0, len(c_buf), 16):
            blocks.append(c_buf[i:(i+size)])
        return blocks
        
    def build_from_chunks(self, chunks):
        return b''.join(chunks)
    
    def get_mutable_block(self, block:bytes) -> bytearray:
        mut = bytearray(len(block))
        i = 0
        for b in block:
            mut[i] = b
            i+=1
        return mut

