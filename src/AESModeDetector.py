
class AESModeDetector:

    def detect_ecb_mode(self, c_buf, block_size=16):
        '''
        ECB MODE: 
        the same block_size bytes of plaintext will yield the same 16 bytes of ciphertext under K
        because of AES, K can be any of the following: 128, 192, 256 bits (16, 24, 32 bytes)
        '''
        d = dict()
        for block in self.break_off_block(c_buf, block_size):
            if block in d.keys():
                d[block] += 1
            else:
                d[block] = 1
        for k in d.keys():
            if d[k] > 1:
                return {
                    'ecb': True,
                    'block': k,
                    'frequency': d[k]
                }
        return {
            'ecb': False,
            'block': '',
            'frequency': 0
        }

    def break_off_block(self, blocks, size):
        i = 1
        prev = 0
        while i < len(blocks)/size:
            y = blocks[prev*size:i*size]
            yield y
            prev = i
            i +=1