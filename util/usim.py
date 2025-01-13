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

import json
import sys

from cryptography.hazmat.primitives               import hashes
from cryptography.hazmat.primitives               import serialization
from cryptography.hazmat.primitives.kdf.concatkdf import ConcatKDFHash

def load_key(filename):
    with open(filename, 'rb') as f:
        return serialization.load_pem_private_key(f.read(), None)

def derive_k(seed):
    ckdf = ConcatKDFHash(hashes.SHA256(), 16, b'USIM K')

    return ckdf.derive(seed.encode())

def main():
    if len(sys.argv) != 3:
        print(f'Usage: {sys.argv[0]} <seed> <HN private key>', file=sys.stderr)
        return 1

    seed, hn_private_key = sys.argv[1:]

    try:
        hn_public_key = load_key(hn_private_key) \
            .public_key()                        \
            .public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    except FileNotFoundError as e:
        print(f'Unable to open HN private key: {e}', file=sys.stderr)

        return 1

    usim = {
        'k'             : derive_k(seed).hex().upper(),
        'mcc'           : '302',
        'mnc'           : '000',
        'msin'          : '000000001',
        'milenageOp'    : '00' * 16,
        'hnPublicKey'   : hn_public_key .hex().upper(),
        'hnPublicKeyId' : '1'
    }

    print()
    print(f'// Seed: {seed}')
    print(json.dumps(usim, indent=4))

    return 0

if __name__ == '__main__':
    exit(main())
