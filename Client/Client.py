from base64 import b32encode

import cryptography.fernet as crypt
import pyotp as otp

from Utils.encryption import encrypt_message_gcm, decrypt_message_gcm
from Utils.Utils import scrypt_message


class Client:
    def __init__(self, shared_salt):
        self.salt = shared_salt
        self.session_key = None
        self.session_iv = None
        with open("Client/secret-totp-client.enc", "r") as fd:
            encrypted_secret = fd.read()
            with open('Client/secret-client.key', 'r') as key_file:
                key = key_file.read()
                cipher = crypt.Fernet(key)

                decrypted_data = cipher.decrypt(encrypted_secret)
                self.secret = b32encode(decrypted_data)

    def screen(self):
        print("\n"*3)
        print("-"*10,"Tela do cliente", "-"*10)

    def choose_dish(self):
        input("Escreva o número do prato: ")

    def set_seesion_encryption_parameters(self, token, user_phone):
        self.session_key = scrypt_message(token, self.salt)
        self.session_iv = scrypt_message(user_phone, self.salt)

    def request_totp(self):
        totp = otp.TOTP(self.secret, interval=60)
        # variavel = totp.provisioning_uri("your@email.com", issuer_name="Carla")
        # codigo_qr = qr.make(totp.now())
        # codigo_qr.show()

        return totp

    def encrypt_message(self, message):
        return encrypt_message_gcm(message, self.session_key, self.session_iv)

    def decrypt_message(self, message, tag):
        return decrypt_message_gcm(message, self.session_key, self.session_iv, tag)


