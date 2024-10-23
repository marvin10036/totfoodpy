from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt


def encrypt_message_gcm(message, key, nonce):

    # Cria cifra GCM/AES
    cipher = Cipher(
        algorithms.AES(key),
        modes.GCM(nonce),
        backend=default_backend()
    )

    encryptor = cipher.encryptor()

    # Encripta a mensagem
    ciphertext = encryptor.update(message.encode()) + encryptor.finalize()

    # Pega a tag/aka hash de confirmação
    tag = encryptor.tag

    return ciphertext, tag

def decrypt_message_gcm(ciphertext, key, nonce, tag):
    cipher = Cipher(
        algorithms.AES(key),
        modes.GCM(nonce, tag),
        backend=default_backend()
    )

    decryptor = cipher.decryptor()

    decrypted_message = decryptor.update(ciphertext) + decryptor.finalize()

    return decrypted_message.decode()
