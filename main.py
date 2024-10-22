import os
from base64 import b32encode

import cryptography.fernet as crypt
import pyotp as otp

import qrcode as qr
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from encryption import encrypt_message_gcm, decrypt_message_gcm
from cryptography.hazmat.backends import default_backend
salt = os.urandom(16)

def scrypt_message(password: str) -> (bytes, bytes):
    # Generate a random salt
    # Create a Scrypt KDF instance
    kdf = Scrypt(
        salt=salt,
        length=32,  # Length of the derived key
        n=16384,     # CPU/memory cost factor
        r=8,         # Block size
        p=1,         # Parallelization factor
        backend=default_backend()
    )
    key = kdf.derive(password.encode())  # Derive the key from the password
    return key


class Client:
    def __init__(self):
        self.session_key = None
        self.session_iv = None
        self.password = "Senha mucho louca"
        with open("secret-totp-client.enc", "r") as fd:
            encrypted_secret = fd.read()
            with open('secret-client.key', 'r') as key_file:
                key = key_file.read()
                cipher = crypt.Fernet(key)

                decrypted_data = cipher.decrypt(encrypted_secret)
                self.secret = b32encode(decrypted_data)
    
    def screen(self):
        print("\n"*3)
        print("-"*10,"Tela do cliente", "-"*10)

    def set_seesion_encryption_parameters(self, token):
        self.session_key = scrypt_message(token)
        self.session_iv = scrypt_message(self.password)

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



class Server:
    def __init__(self):
        self.session_key = None
        self.session_nonce = None
        with open("secret-totp-server.enc", "r") as fd:
            encrypted_secret = fd.read()
            with open('secret-server.key', 'r') as key_file:
                key = key_file.read()
                cipher = crypt.Fernet(key)

                # O algoritmo do TOTP precisava de base32 encoding
                decrypted_data = cipher.decrypt(encrypted_secret)
                self.secret = b32encode(decrypted_data)
    
    def screen(self,):
        print("\n"*3)
        print("-"*10,"Tela do Servidor", "-"*10)

    def request_totp(self):
        totp = otp.TOTP(self.secret, interval=60)
        return totp

    def __set_session_key(self, token):
        self.session_key = token

    def is_user_totp_valid(self):
        user_input = input("Insira o código 2FA: ")
        if self.request_totp().verify(user_input):
            self.__set_session_key(scrypt_message(user_input))
            self.gen_nonce()
            print("Sessão validada")
            return True, user_input
        return False, None

    def gen_nonce(self, user_password="Senha mucho louca"): 
       self.session_nonce = scrypt_message(user_password)

    def encrypt_message(self, message):
        return encrypt_message_gcm(message, self.session_key, self.session_iv)

    def decrypt_message(self, message, tag):
        return decrypt_message_gcm(message, self.session_key, self.session_iv, tag)

def main():
    sv = Server()
    cl = Client()

    cl.screen()
    print("TOTP no celular do usuário: ", cl.request_totp().now())

    sv.screen()
    is_session_valid, key = sv.is_user_totp_valid()

    if is_session_valid:
        cl.set_seesion_encryption_parameters(key)
    else:
        print("Sessão inválida")
        return

    cl.screen()
    crypted_message, tag = encrypt_message_gcm("Mensagem secreta", cl.session_key, cl.session_iv)

    decrypted_message = decrypt_message_gcm(crypted_message, sv.session_key, sv.session_nonce, tag)

    print(decrypted_message)

main()
