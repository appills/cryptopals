def hamming_distance(p, q):
    len_p = len(p)
    len_q = len(q)
    min_len = min(len_p, len_q)
    # this is the number of differing bits up to min_len
    xors = [bin(p[i] ^ q[i]) for i in range(0, min_len)]
    # count number of 1's
    ham = ''.join(xors).count('1')
    extra = [0]
    if len_p < len_q:
        extra = [bin(x).count('1') for x in q[len_p-len_q:]]
    elif len_q < len_p:
        extra = [bin(x).count('1') for x in p[len_q-len_p:]]
    return ham + sum(extra)