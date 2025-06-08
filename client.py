import socket
import pickle
import rsa
import rsa.core
import rsa.transform
import rsa.common

def encrypt_with_private_key(message, priv_key):
    """Шифрование закрытым ключом отправителя (подпись)"""
    message_int = rsa.transform.bytes2int(message)
    encrypted_int = rsa.core.encrypt_int(message_int, priv_key.d, priv_key.n)
    block_size = rsa.common.byte_size(priv_key.n)
    return rsa.transform.int2bytes(encrypted_int, block_size)

def decrypt_with_public_key(ciphertext, pub_key):
    """Расшифрование открытым ключом отправителя (проверка подписи)"""
    cipher_int = rsa.transform.bytes2int(ciphertext)
    message_int = rsa.core.encrypt_int(cipher_int, pub_key.e, pub_key.n)
    block_size = rsa.common.byte_size(pub_key.n)
    return rsa.transform.int2bytes(message_int, block_size)

def main():
    # Генерация ключей клиента
    client_pubkey, client_privkey = rsa.newkeys(2048)
    
    # Подключение к серверу
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(('localhost', 12345))
    print("Подключено к серверу")
    
    try:
        # Обмен ключами
        client_socket.send(pickle.dumps(client_pubkey))
        server_pubkey = pickle.loads(client_socket.recv(4096))
        
        # Отправка сообщения
        message = b"Hello from client!"
        signature = encrypt_with_private_key(message, client_privkey)
        signature_int = rsa.transform.bytes2int(signature)
        encrypted_int = rsa.core.encrypt_int(signature_int, server_pubkey.e, server_pubkey.n)
        encrypted_msg = rsa.transform.int2bytes(encrypted_int, rsa.common.byte_size(server_pubkey.n))
        client_socket.send(encrypted_msg)
        print("Сообщение отправлено")
        
        # Получение ответа
        encrypted_resp = client_socket.recv(4096)
        encrypted_resp_int = rsa.transform.bytes2int(encrypted_resp)
        signature_resp_int = rsa.core.decrypt_int(encrypted_resp_int, client_privkey.d, client_privkey.n)
        signature_resp = rsa.transform.int2bytes(signature_resp_int, rsa.common.byte_size(client_privkey.n))
        response = decrypt_with_public_key(signature_resp, server_pubkey)
        print(f"Ответ сервера: {response.decode()}")
        
    except Exception as e:
        print(f"Ошибка: {e}")
    finally:
        client_socket.close()

if __name__ == "__main__":
    main()