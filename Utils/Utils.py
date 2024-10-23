import os

from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.backends import default_backend


def scrypt_message(password: str, shared_salt) -> (bytes, bytes):
    # Generate a random salt
    # Create a Scrypt KDF instance
    kdf = Scrypt(
        salt=shared_salt,
        length=32,  # Length of the derived key
        n=16384,     # CPU/memory cost factor
        r=8,         # Block size
        p=1,         # Parallelization factor
        backend=default_backend()
    )
    key = kdf.derive(password.encode())  # Derive the key from the password
    return key

