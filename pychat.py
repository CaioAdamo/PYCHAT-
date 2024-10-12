#Implementação de bibliotecas necessárias para construção do código.
import bcrypt
import base64
import os
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
from pymongo import MongoClient

# Conexão com do codigo em python com o MongoDB
client = MongoClient('mongodb://localhost:27017/')
db = client['pychat']
users_collection = db['users']
messages_collection = db['messages']

#Gerador de chaves para criptografia de qualquer mensagem trocada por Bob ou Alice (PBE PKCS5)
def gerar_chave(senha, sal):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=sal,
        iterations=100000,
        backend=default_backend()
    )
    chave = base64.urlsafe_b64encode(kdf.derive(senha.encode()))
    return chave

# Essa função realiza o cadastro de um novo usuario no chat e geração de uma chave criptografada.
def register_user(username, password):
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password.encode(), salt)
    users_collection.insert_one({"username": username, "password": hashed_password}
    print(f"Usuário {username} registrado com sucesso!")

# Essa função realiza a autenticação de um usuário no chat.
def authenticate_user(username, password):
    user = users_collection.find_one({"username": username})
    if user and bcrypt.checkpw(password.encode(), user['password']):
        print("Autenticação bem-sucedida!")
        return True
    else:
        print("Usuário ou senha incorretos.")
        return False

# Função responsavel por criptografar as mensagens.
def criptografa_message(message, key):
    fernet = Fernet(key)
    criptografia_message = fernet.encrypt(message.encode())
    return criptografa_message

# Função responsavel por descriptografar mensagens.
def descriptografa_message(encrypted_message, key):
    fernet = Fernet(key)
    descriptografia_message = fernet.decrypt(descriptografa_message).decode()
    return descriptografa_message

# Função responsavel por enviar uma mensagem criptografada
def envia_message(sender, receiver, message, shared_password):
    salt = os.urandom(16)
    key = generate_key(shared_password, salt)

    criptografia_message = criptografa_message(message, key)

    messages_collection.insert_one({
        "Nome": nome,
        "Destinatario": destinatario,
        "mensagem": criptografia_message
    })
    print(f"Mensagem enviada com sucesso!")

# Função responsavel por exibir a mensagem recebida ao destinatario.
def read_messages(receiver, shared_password):
    messages = messages_collection.find({"receiver": receiver})
    for msg in messages:
        salt = msg['salt']
        key = generate_key(shared_password, salt)
        descritografia_message = descriptografa_message(msg['message'], key)
        print(f"De {msg['sender']}: {decrypted_message}")


if __name__ == "__main__":
    register_user("Bob", "CaioAdamo")
    register_user("Alice", "VictorFogale")

    if authenticate_user("Bob", "CaioAdamo"):
        send_message("Bob", "Alice", "Teste chatpy", "chave")

    read_messages("Alice", "chave")