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
    # Генерация ключей сервера
    server_pubkey, server_privkey = rsa.newkeys(2048)
    
    # Настройка сокета
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('localhost', 12345))
    server_socket.listen(1)
    print("Сервер запущен. Ожидание подключения...")
    
    conn, addr = server_socket.accept()
    print(f"Подключен клиент: {addr}")
    
    try:
        # Обмен ключами
        client_pubkey = pickle.loads(conn.recv(4096))
        conn.send(pickle.dumps(server_pubkey))
        
        # Прием сообщения от клиента
        encrypted_msg = conn.recv(4096)
        
        # Расшифровка сообщения
        encrypted_int = rsa.transform.bytes2int(encrypted_msg)
        signature_int = rsa.core.decrypt_int(encrypted_int, server_privkey.d, server_privkey.n)
        block_size = rsa.common.byte_size(server_privkey.n)
        signature = rsa.transform.int2bytes(signature_int, block_size)
        message = decrypt_with_public_key(signature, client_pubkey)
        
        print(f"Получено сообщение: {message.decode()}")
        
        # Отправка ответа
        response = b"Hello from server!"
        signature_resp = encrypt_with_private_key(response, server_privkey)
        signature_resp_int = rsa.transform.bytes2int(signature_resp)
        encrypted_resp_int = rsa.core.encrypt_int(signature_resp_int, client_pubkey.e, client_pubkey.n)
        encrypted_resp = rsa.transform.int2bytes(encrypted_resp_int, rsa.common.byte_size(client_pubkey.n))
        conn.send(encrypted_resp)
        print("Ответ отправлен")
        
    except Exception as e:
        print(f"Ошибка: {e}")
    finally:
        conn.close()
        server_socket.close()

if __name__ == "__main__":
    main()