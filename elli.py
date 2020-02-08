from os import urandom
from eccsnacks.curve25519 import scalarmult, scalarmult_base
import binascii
import base64
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet


# Generate the key pair for the reader
r_private = urandom(32)
r_public = scalarmult_base(r_private)

# Generate the key pair for the tag
t_private = urandom(32)
t_public = scalarmult_base(t_private)

# The reader and the tag generate the shared key, following an exchange of public keys
r_shared = scalarmult(r_private, t_public)
t_shared = scalarmult(t_private, r_public)

# Check that the transmitted values match
if r_shared == t_shared:
    print "Keys exchanged."
    print "Reader: ",binascii.hexlify(r_shared)
    print "Tag:    ",binascii.hexlify(t_shared)
else:
    print "Error in key exchange."
    exit

# Generate a message for the tag to send to the reader
message = "Hello, I am T.".encode()

# Use the shared key to derive a key
shared_master_key = binascii.hexlify(t_shared).encode()
salt = urandom(32)
kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=salt,
    iterations=100000,
    backend=default_backend()
)
derived_key = base64.urlsafe_b64encode(kdf.derive(shared_master_key))

f = Fernet(derived_key)
encrypted = f.encrypt(message)
decrypted = f.decrypt(encrypted)
print "Message:           ",message.decode()
print "Message sent:      ",encrypted
print "Message decrypted: ",decrypted.decode()
