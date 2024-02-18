def pkcs7_pad(block, block_size=16):
    block_len = len(block)
    if block_len % block_size == 0:
        return block
    else:
        # take the last block_len%block_size bytes 
        last_block_size = block_len % block_size
        # check how far we are from a full block
        pad_size = block_size - last_block_size
        return block + pad(pad_size, pad_size)
    
def pad(byte, pad_size):
    return byte.to_bytes() * pad_size

def strip_pkcs7_pad(block, block_size=16):
    block_len = len(block)
    if block_len % block_size == 0:
        # check last byte
        last_byte = block[-1]
        if last_byte > 0 and last_byte < block_size:
            return block[0:(-1*last_byte)]
    return block

def throw_bad_padding(block, block_size=16):
    block_len = len(block)
    if block_len % block_size == 0:
        # check last byte
        last_byte = block[-1]
        pad_bytes = block[(-1*last_byte):]
        for pad_byte in pad_bytes:
            if pad_byte != last_byte:
                raise Exception("Bad padding")

