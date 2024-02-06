import src.utils.bytecodec as bytecodec

'''
utils to help parse those formatted txt files
'''

def read_formatted_base64_file(path):
    with open(path, 'r') as fh:
        encoded = ''.join([line.rstrip() for line in fh])
    return bytecodec.base64_to_bytes(encoded)