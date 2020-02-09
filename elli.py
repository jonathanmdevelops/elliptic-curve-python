"""ELLI Lightweight Cryptography Demonstration

This script demonstrates a DH Key Exchange and Public Key Signing using Elliptic Curves between an RFID reader and tag.
"""

from os import urandom
from eccsnacks.curve25519 import scalarmult, scalarmult_base
from sys import exit
import binascii
import base64
import hashlib
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet

# Encrypts and decrypts data with AES given a key
def encrypt(input_key, message, salt, is_encryption_mode=True):
    # Use the shared key to derive a key
    shared_master_key = binascii.hexlify(input_key).encode()
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    derived_key = base64.urlsafe_b64encode(kdf.derive(shared_master_key))

    f = Fernet(derived_key)
    # Dependent on the mode, either encrypt or decrypt
    if is_encryption_mode:
        return f.encrypt(message.encode())
    else:
        return f.decrypt(message).decode()

# Generate the key pair for the reader
r_private = urandom(32)
r_public = scalarmult_base(r_private)

# Generate the key pair for the tag
t_private = urandom(32)
t_public = scalarmult_base(t_private)

# Sign the Public Key of the tag with the Private Key of the reader
certificate_salt = urandom(32)
t_public_hash = hashlib.sha256(t_public).hexdigest()
t_certificate = encrypt(r_private, t_public_hash, certificate_salt)

print "Reader Public Key: ",binascii.hexlify(r_public)
print "Reader Private Key:",binascii.hexlify(r_private)
print

print "Tag Public Key:    ",binascii.hexlify(t_public)
print "Tag Private Key:   ",binascii.hexlify(t_private)
print "Tag Public Hash:   ",t_public_hash
print "Tag Certificate:   ",t_certificate
print

# Authenticate the tag's public key
expected_t_public_hash = encrypt(r_private, t_certificate, certificate_salt, False)
if t_public_hash == expected_t_public_hash:
    print "Tag authenticated."
    print
else:
    print "Tag is not authentic."
    exit()

# The reader and the tag generate the shared key, following an exchange of public keys
r_shared = scalarmult(r_private, t_public)
t_shared = scalarmult(t_private, r_public)

# Check that the transmitted values match
if r_shared == t_shared:
    print "Keys exchanged."
    print "Reader: ",binascii.hexlify(r_shared)
    print "Tag:    ",binascii.hexlify(t_shared)
    print
else:
    print "Error in key exchange."
    exit()

# Generate a message for the tag to send to the reader
message = "Hello, I am T."
message_salt = urandom(32)
encrypted = encrypt(t_shared, message, message_salt)
decrypted = encrypt(t_shared, encrypted, message_salt, False)

print "Message:           ",message
print "Message sent:      ",encrypted
print "Message decrypted: ",decrypted
