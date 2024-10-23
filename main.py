
from Server.Server import Server
from Client.Client import Client


def main():
    sv = Server()
    cl = Client()

    sv.screen()
    sv.show_dishes()

    cl.screen()
    cl.choose_dish()

    sv.screen()
    user_phone = sv.ask_user_phone()

    cl.screen()
    print("TOTP no celular do usuário: ", cl.request_totp().now())

    sv.screen()
    is_session_valid, key = sv.is_user_totp_valid()

    if is_session_valid:
        cl.set_seesion_encryption_parameters(key, user_phone)
    else:
        print("Sessão inválida")
        return

    cl.screen()
    print("Cliente está fazendo o pagamento...")
    print("Cliente vai encriptar o \"Comprovante do pagamento\" ...")
    crypted_message, tag = cl.encrypt_message("Comprovante do pagamento")
    print("Cliente envia a mensagem criptografada")

    sv.screen()
    print("Servidor recebe a mensagem")
    print("Servidor vai decriptar a mensagem")
    decrypted_message = sv.decrypt_message(crypted_message, tag)
    print("A mensagem decriptada é: ", decrypted_message)
    print("Servidor envia pedido para o restaurante")

    sv.screen()
    print("Servidor vai encriptar: \" Pedido confirmado. Horário previsto de entrega é 19h\"")

    crypted_message, tag = sv.encrypt_message("Pedido confirmado. Horário previsto de entrega é 19h")
    print("Servidor envia a mensagem criptografada")

    cl.screen()
    print("Cliente recebe a mensagem")
    print("Cliente decripta a mensagem ...")
    decrypted_message = cl.decrypt_message(crypted_message, tag)
    print("Mensagem decriptada é: ", decrypted_message)


main()
