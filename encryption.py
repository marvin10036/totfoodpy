from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

def encrypt_message_gcm(message, key, nonce):
    # Generate a random 12-byte (96-bit) nonce

    # Create AES-GCM cipher
    cipher = Cipher(
        algorithms.AES(key),
        modes.GCM(nonce),
        backend=default_backend()
    )
    
    encryptor = cipher.encryptor()

    # Encrypt the message
    ciphertext = encryptor.update(message.encode()) + encryptor.finalize()

    # Get the GCM tag
    tag = encryptor.tag

    return ciphertext, tag

def decrypt_message_gcm(ciphertext, key, nonce, tag):
    # Create AES-GCM cipher
    cipher = Cipher(
        algorithms.AES(key),
        modes.GCM(nonce, tag),
        backend=default_backend()
    )
    
    decryptor = cipher.decryptor()

    # Decrypt the ciphertext
    decrypted_message = decryptor.update(ciphertext) + decryptor.finalize()

    return decrypted_message.decode()