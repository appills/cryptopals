# XORs two bytearrays
def array_xor(buf_a: bytes, buf_b: bytes) -> bytearray:
	buf_len = len(buf_a)
	buf = bytearray(buf_len)
	if buf_len == len(buf_b):
		i = 0
		while i < buf_len:
			buf[i] = (buf_a[i] ^ buf_b[i])
			i += 1
	return buf

def bruteforce_single_byte_xor(buf: bytes) -> list:
	a = [bytearray()]*256
	for i in range(0, 256):
		res = single_byte_xor(buf, i)
		a[i] = res
	return a

def single_byte_xor(buf: bytes, byte: int) -> bytearray:
	byte_str_len = len(buf)
	byte_buf = bytearray([byte]*byte_str_len)
	return array_xor(buf, byte_buf)
	
def repeating_key_xor(k_buf, p_buf) -> bytearray:
	key_buf = get_repeating_key_buf(k_buf, len(p_buf))
	return array_xor(p_buf, key_buf)

def get_repeating_key_buf(k_buf, p_len) -> bytearray:
	buf = bytearray([0]*p_len)
	k_len = len(k_buf)
	for i in range(0, p_len):
		buf[i] = k_buf[i % k_len]
	return buf