#!/usr/bin/env python3

# Copyright (c) 2024 Julian Parkin
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import random

from cryptography.hazmat.primitives        import hashes
from cryptography.hazmat.primitives.hmac   import HMAC

def rand_bytes(n):
    return bytes(random.randint(0, 255) for _ in range(n))

def enc_len(n):
    assert n < 256
    return bytes((0, n))

def kdf(k, fc, data):
    hmac = HMAC(k, hashes.SHA256())

    hmac.update(bytes((fc,)))

    for d in data:
        hmac.update(d)
        hmac.update(enc_len(len(d)))

    return hmac.finalize()

def output_arr(name, val):
    print(f'{name} = hex.parseHex("', end='')
    for v in val:
        print(f'{v:02X}', end='')
    print('");')

if __name__ == '__main__':

    random.seed(591874)

    rand = rand_bytes(16)
    sqn  = rand_bytes( 6)
    res  = rand_bytes( 8)
    ck   = rand_bytes(16)
    ik   = rand_bytes(16)
    ak   = rand_bytes( 6)

    snn  = b'5G:mnc015.mcc234.3gppnetwork.org'
    supi = b'user@example.com'
    abba = bytes((0, 0))

    sqn_enc = bytes(x ^ y for x, y in zip(sqn, ak))

    k_ausf   = kdf(ck + ik, 0x6A, (snn, sqn_enc))
    res_star = kdf(ck + ik, 0x6B, (snn, rand, res))[:16]
    k_seaf   = kdf(k_ausf,  0x6C, (snn,))
    k_amf    = kdf(k_seaf,  0x6D, (supi, abba))

    digest = hashes.Hash(hashes.SHA256())

    digest.update(rand)
    digest.update(res_star)

    h_res_star = digest.finalize()[:16]

    print(f'public static final String SNN  = "{snn.decode()}";')
    print(f'public static final String SUPI = "{supi.decode()}";')
    print()
    output_arr('RAND', rand)
    output_arr('SQN',  sqn)
    output_arr('RES',  res)
    output_arr('CK',   ck)
    output_arr('IK',   ik)
    output_arr('AK',   ak)
    output_arr('ABBA', abba)
    print()
    output_arr('SQN_ENC',    sqn_enc)
    output_arr('K_AUSF',     k_ausf)
    output_arr('RES_STAR',   res_star)
    output_arr('H_RES_STAR', h_res_star)
    output_arr('K_SEAF',     k_seaf)
    output_arr('K_AMF',      k_amf)
