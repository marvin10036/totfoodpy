import cryptography.fernet as crypt


# Essa função só foi usada para gerar as chaves iniciais do server e do
# client, simulando o salvamento prévio da chave em ambos os lados no cadastro
# ela não é usada/importada mais no fluxo da aplicação

def encrypt_file(file_name):
    key = crypt.Fernet.generate_key()
    # Salvando chave em arquivo
    with open('secret-client.key', 'wb') as key_file:
        key_file.write(key)

    cipher = crypt.Fernet(key)
    with open(file_name, 'rb') as file:
        data = file.read()
    encrypted_data = cipher.encrypt(data)
    with open(file_name + '.enc', 'wb') as enc_file:
        enc_file.write(encrypted_data)


encrypt_file("secret-totp-client")
