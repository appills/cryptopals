from base64 import b64encode, b64decode

'''
util for consistent naming of byte <-> string conversions
'''

# hex_str: str, return bytes
def hex_to_bytes(hex_str) -> bytes:
    return bytes.fromhex(hex_str)
# buf: bytes, return str
def bytes_to_hex(buf) -> str:
    return buf.hex()
# buf: bytes, return str
def bytes_to_base64(buf) -> str:
    return b64encode(buf).decode()
# b64_str: str, return bytes
def base64_to_bytes(b64_str) -> bytes:
    return b64decode(b64_str)
# bytes b'foobar' to utf-8 string ('foobar')
def bytes_to_utf8(byts: bytes) -> str:
    return bytes.decode(byts, 'utf-8') 
# utf-8 string (e.g. 'foobar'), return bytes (b'foobar')
def utf8_to_bytes(s: str) -> bytes:
    return s.encode('utf-8')