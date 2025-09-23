import socket
import os
import threading
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

# This function will run in its own thread to handle sending messages
def send_messages(sock, aes):
    while True:
        message_to_send = input()
        
        # ADDED LOGGING
        print("-> Encrypting your message...")
        nonce = os.urandom(12)
        plaintext = message_to_send.encode('utf-8')
        ciphertext = aes.encrypt(nonce, plaintext, None)
        sock.sendall(nonce)
        sock.sendall(ciphertext)
        print("-> Message sent!")
        
        if message_to_send.strip().lower() == 'exit':
            os._exit(0)

# --- 1. Setup the Server ---
host = '0.0.0.0'
port = 9999
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind((host, port))
server_socket.listen()
print(f"✅ Server is listening for connections on port {port}")

while True:
    client_socket, addr = server_socket.accept()
    print(f"🤝 Got a new connection from {addr}")

    try:
        # --- PHASE 2: DIFFIE-HELLMAN KEY EXCHANGE ---
        print("\n[Phase 2] Performing Diffie-Hellman key exchange...")
        parameters = dh.generate_parameters(generator=2, key_size=2048)
        server_private_key = parameters.generate_private_key()
        params_bytes = parameters.parameter_bytes(serialization.Encoding.PEM, serialization.ParameterFormat.PKCS3)
        server_public_key_bytes = server_private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        client_socket.sendall(params_bytes)
        client_socket.sendall(server_public_key_bytes)
        client_public_key_bytes = client_socket.recv(2048)
        client_public_key = serialization.load_pem_public_key(client_public_key_bytes)
        shared_key = server_private_key.exchange(client_public_key)
        derived_key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b'handshake_data').derive(shared_key)
        
        print(f"✅ Secure shared key established!")
        # ADDED LOGGING (FOR DEMONSTRATION ONLY)
        print(f"   AES-256 Key (in hex): {derived_key.hex()}\n")
        
        aesgcm = AESGCM(derived_key)

        send_thread = threading.Thread(target=send_messages, args=(client_socket, aesgcm))
        send_thread.daemon = True
        send_thread.start()

        # --- PHASE 3: SECURE RECEIVING LOOP ---
        while True:
            nonce = client_socket.recv(12)
            if not nonce: break
            ciphertext = client_socket.recv(1024)
            if not ciphertext: break
            
            try:
                # ADDED LOGGING
                print("\n<- Received new data, decrypting...")
                plaintext = aesgcm.decrypt(nonce, ciphertext, None)
                message = plaintext.decode('utf-8')
                print(f"Decrypted message: '{message}'") # MODIFIED
                
                if message.strip().lower() == 'exit':
                    os._exit(0)
            except InvalidTag:
                print("⚠️  Received a tampered message!")
                break
            
    except Exception as e:
        print(f"An error occurred: {e}")
    finally:
        print(f"🔌 Connection with {addr} has been closed.")
        client_socket.close()
