import pyotp as otp
import qrcode as qr
import cryptography.fernet as crypt
from base64 import b32encode


class Client:
    def __init__(self):
        with open("secret-totp-client.enc", "r") as fd:
            encrypted_secret = fd.read()
            with open('secret-client.key', 'r') as key_file:
                key = key_file.read()
                cipher = crypt.Fernet(key)

                decrypted_data = cipher.decrypt(encrypted_secret)
                self.secret = b32encode(decrypted_data)

    def request_totp(self):
        totp = otp.TOTP(self.secret, interval=60)
        # variavel = totp.provisioning_uri("your@email.com", issuer_name="Carla")
        codigo_qr = qr.make(totp.now())
        codigo_qr.show()

        return totp


class Server:
    def __init__(self):
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


def main():
    sv = Server()
    cl = Client()

    print("Tela do servidor")
    totp_sv = sv.request_totp()

    print("Tela do cliente")
    cl.request_totp()

    otp_input = input("Insira o código 2FA: ")

    # Verificação do servidor
    if totp_sv.verify(otp_input) and otp_input == totp_sv.now():
        print("Código 2FA válido.")
    else:
        print("Código 2FA inválido.")
        return False

    print("Tela do cliente")


main()
