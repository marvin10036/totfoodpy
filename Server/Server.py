from base64 import b32encode

import cryptography.fernet as crypt
import pyotp as otp

from Utils.encryption import encrypt_message_gcm, decrypt_message_gcm
from Utils.Utils import scrypt_message


class Server:
    def __init__(self):
        self.salt = self.get_salt()
        self.session_key = None
        self.session_iv = None

        with open("Server/secret-totp-server.enc", "r") as fd:
            encrypted_secret = fd.read()
            with open('Server/secret-server.key', 'r') as key_file:
                key = key_file.read()
                cipher = crypt.Fernet(key)

                # O algoritmo do TOTP precisava de base32 encoding
                decrypted_data = cipher.decrypt(encrypted_secret)
                self.secret = b32encode(decrypted_data)

    def screen(self,):
        print("\n"*3)
        print("-"*10, "Tela do Servidor", "-"*10)

    def show_dishes(self):
        print("Escolha um prato: ")

        print("1 - Arroz e Feijão - R$ 25,00",
              "2 - Pizza Calabresa - R$ 30,00",
              "3 - Nhoque - R$ 40,00",
              "4 - Salada - R$ 20,00",
              "5 - Linguiça - R$ 20,00")

    def ask_user_phone(self):
        user_phone = input("Qual seu número de telefone: ")
        self.gen_iv(user_phone)
        return user_phone

    def request_totp(self):
        totp = otp.TOTP(self.secret, interval=60)
        return totp

    def __set_session_key(self, token):
        self.session_key = token

    def is_user_totp_valid(self):
        user_input = input("Insira o código 2FA: ")
        if self.request_totp().verify(user_input):
            self.__set_session_key(scrypt_message(user_input, self.salt))
            print("Sessão validada")
            return True, user_input
        return False, None

    def get_salt(self):
        with open("Server/Stored-salt", "rb") as fd:
            salt = fd.read()
        return salt

    # Gera o IV a partir de chave derivada do telefone do usuario
    def gen_iv(self, user_phone):
        self.session_iv = scrypt_message(user_phone, self.salt)

    def encrypt_message(self, message):
        return encrypt_message_gcm(message, self.session_key, self.session_iv)

    def decrypt_message(self, message, tag):
        return decrypt_message_gcm(message, self.session_key, self.session_iv, tag)

