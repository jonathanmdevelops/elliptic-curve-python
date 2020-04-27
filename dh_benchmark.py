"""
Lightweight Cryptography comparison.

This script aims to compare the performance of ECDH (ELLI) to traditional DH key exchange.
"""

import datetime
from os import urandom

from eccsnacks.curve25519 import scalarmult, scalarmult_base

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import dh

elli_key_size = 256
elli_byte_size = 256/8

traditional_key_size = 512

def elli(key_size_bytes):
    # Generate the key pair for Alice
    a_private = urandom(key_size_bytes)
    a_public = scalarmult_base(a_private)

    # Generate the key pair for Bob
    b_private = urandom(key_size_bytes)
    b_public = scalarmult_base(b_private)

    a_shared = scalarmult(a_private, b_public)
    b_shared = scalarmult(b_private, a_public)

    assert a_shared == b_shared

def traditional_dh(key_size_bits):
    parameters = dh.generate_parameters(generator=2, key_size=key_size_bits,
                                     backend=default_backend())

    a_private = parameters.generate_private_key()
    b_private = parameters.generate_private_key()

    a_shared = a_private.exchange(b_private.public_key())
    b_shared = b_private.exchange(a_private.public_key())

    assert a_shared == b_shared

key_size_bits = [512, 1024, 2048]

elli_start = datetime.datetime.now()
elli(32)
elli_end = datetime.datetime.now()
elli_time = str(elli_end - elli_start)
print("256-bit ELLI\t" + elli_time)

for key in key_size_bits:
    traditional_start = datetime.datetime.now()
    traditional_dh(key)
    traditional_end = datetime.datetime.now()

    traditional_time = str(traditional_end - traditional_start)

    print(str(key) + "-bit DH\t" + traditional_time)
