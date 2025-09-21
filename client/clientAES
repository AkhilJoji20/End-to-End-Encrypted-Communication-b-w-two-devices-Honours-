import socket
import os
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

# --- 1. Setup the Client ---
host = '192.168.221.231' # IMPORTANT: Change to server's LOCAL IP
port = 9999
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

try:
    # --- 2. Connect to the Server ---
    print(f"Attempting to connect to {host}:{port}...")
    client_socket.connect((host, port))
    print("✅ Successfully connected to the server.")

    # --- PHASE 2: DIFFIE-HELLMAN KEY EXCHANGE ---
    print("\n[Phase 2] Performing Diffie-Hellman key exchange...")
    params_bytes = client_socket.recv(2048)
    server_public_key_bytes = client_socket.recv(2048)
    
    parameters = serialization.load_pem_parameters(params_bytes)
    server_public_key = serialization.load_pem_public_key(server_public_key_bytes)
    
    client_private_key = parameters.generate_private_key()
    client_public_key_bytes = client_private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    client_socket.sendall(client_public_key_bytes)
    
    shared_key = client_private_key.exchange(server_public_key)
    
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'handshake_data',
    ).derive(shared_key)

    print(f"✅ Secure shared key established!\n")
    aesgcm = AESGCM(derived_key)

    # ======================================================================
    # --- PHASE 3: SECURE COMMUNICATION LOOP ---
    # ======================================================================

    print("Chat started. Your messages are now end-to-end encrypted.")
    while True:
        message_to_server = input("You: ")
        
        # Encrypt the message before sending
        nonce = os.urandom(12)
        plaintext = message_to_server.encode('utf-8')
        ciphertext = aesgcm.encrypt(nonce, plaintext, None)

        # Send nonce and ciphertext
        client_socket.sendall(nonce)
        client_socket.sendall(ciphertext)
        
        if message_to_server.strip().lower() == 'exit':
            break

        # Receive the encrypted response from the server
        response_nonce = client_socket.recv(12)
        response_ciphertext = client_socket.recv(1024)

        try:
            # Decrypt and verify the response
            response_plaintext = aesgcm.decrypt(response_nonce, response_ciphertext, None)
            print(f"Server says: '{response_plaintext.decode('utf-8')}'")
        except InvalidTag:
            print("⚠️  Received a tampered or corrupt message from the server!")
            break

except Exception as e:
    print(f"An error occurred: {e}")
finally:
    print("🔌 Disconnecting from the server.")
    client_socket.close()
