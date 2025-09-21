import socket
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

# --- 1. Setup the Client ---
host = '192.168.221.231' # IMPORTANT: Change to server's LOCAL IP
port = 9999
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

try:
    # --- 2. Connect to the Server ---
    print(f"Attempting to connect to {host}:{port}...")
    client_socket.connect((host, port))
    print("✅ Successfully connected to the server.")

    # ======================================================================
    # --- PHASE 2: DIFFIE-HELLMAN KEY EXCHANGE (CLIENT SIDE) ---
    # ======================================================================
    print("\n[Phase 2] Performing Diffie-Hellman key exchange...")

    # 1. Client receives the public parameters and server's public key.
    params_bytes = client_socket.recv(2048)
    server_public_key_bytes = client_socket.recv(2048)

    # 2. Client loads the parameters and the server's public key from bytes.
    parameters = serialization.load_pem_parameters(params_bytes)
    server_public_key = serialization.load_pem_public_key(server_public_key_bytes)
    print("   <- Received DH parameters and server's public key.")

    # 3. Client generates its own private/public key pair using the same parameters.
    client_private_key = parameters.generate_private_key()
    client_public_key_bytes = client_private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # 4. Client sends its public key to the server.
    client_socket.send(client_public_key_bytes)
    print("   -> Sent client's public key to server.")

    # 5. Client computes the shared secret.
    shared_key = client_private_key.exchange(server_public_key)

    # 6. VERY IMPORTANT: Derive the final key, same as the server.
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'handshake_data',
    ).derive(shared_key)

    print(f"✅ Secure shared key established!\n")
    # `derived_key` is now identical to the server's and ready for AES.

    # ======================================================================
    # --- PHASE 1: COMMUNICATION LOOP (Now secure in theory) ---
    # ======================================================================

    print("Type your message (or 'exit' to quit):")
    while True:
        message_to_server = input("You: ")
        
        # In Phase 3, we will encrypt this message using the derived_key.
        client_socket.send(message_to_server.encode('utf-8'))
        if message_to_server.strip().lower() == 'exit':
            break

        # In Phase 3, this will be encrypted data.
        data = client_socket.recv(1024)
        print(f"Server (raw): '{data.hex()}'")

except Exception as e:
    print(f"An error occurred: {e}")
finally:
    print("🔌 Disconnecting from the server.")
    client_socket.close()
