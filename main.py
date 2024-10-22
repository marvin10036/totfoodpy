import pyotp as otp
import qrcode as qr
import cryptography.fernet as crypt
from base64 import b32encode
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.backends import default_backend
import os

salt = os.urandom(16)
def hash_token(password: str) -> (bytes, bytes):
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
        with open("secret-totp-client.enc", "r") as fd:
            encrypted_secret = fd.read()
            with open('secret-client.key', 'r') as key_file:
                key = key_file.read()
                cipher = crypt.Fernet(key)

                decrypted_data = cipher.decrypt(encrypted_secret)
                self.secret = b32encode(decrypted_data)
    
    def set_seesion_key(self, token):
        self.session_key = hash_token(token)
        print(self.session_key)

    def request_totp(self):
        totp = otp.TOTP(self.secret, interval=60)
        # variavel = totp.provisioning_uri("your@email.com", issuer_name="Carla")
        # codigo_qr = qr.make(totp.now())
        # codigo_qr.show()

        return totp
    
    def __ecrypt_message(self, message):
        pass

    def __decrypt_message(self, message):
        pass



class Server:
    def __init__(self):
        self.session_key = None
        with open("secret-totp-server.enc", "r") as fd:
            encrypted_secret = fd.read()
            with open('secret-server.key', 'r') as key_file:
                key = key_file.read()
                cipher = crypt.Fernet(key)

                # O algoritmo do TOTP precisava de base32 encoding
                decrypted_data = cipher.decrypt(encrypted_secret)
                self.secret = b32encode(decrypted_data)

    def request_totp(self):
        totp = otp.TOTP(self.secret, interval=60)
        return totp

    def __set_session_key(self, token):
        self.session_key = token

    def is_user_totp_valid(self):
        user_input = input("Insira o código 2FA: ")
        if self.request_totp().verify(user_input):
            self.__set_session_key(user_input)
            print("Sessão validada")
            return True, user_input
        return False, None
        

def main():
    sv = Server()
    cl = Client()

    print("Tela do cliente")
    print("TOTP no celular do usuário: ", cl.request_totp().now())

    print("Tela do servidor")
    is_session_valid, key = sv.is_user_totp_valid()

    if is_session_valid:
        cl.set_seesion_key(key)
    else:
        print("Sessão inválida")
        return

    print("Tela do cliente")


main()
