import socket
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

# --- 1. Setup the Server (Same as before) ---
host = '0.0.0.0'
port = 9999
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind((host, port))
server_socket.listen()
print(f"✅ Server is listening for connections on port {port}")

# --- 2. Main Server Loop ---
while True:
    client_socket, addr = server_socket.accept()
    print(f"🤝 Got a new connection from {addr}")

    try:
        # ======================================================================
        # --- PHASE 2: DIFFIE-HELLMAN KEY EXCHANGE (SERVER SIDE) ---
        # ======================================================================
        print("\n[Phase 2] Performing Diffie-Hellman key exchange...")

        # 1. Server generates DH parameters and its own private/public key pair.
        #    In a real application, you'd use pre-defined, standardized parameters.
        parameters = dh.generate_parameters(generator=2, key_size=2048)
        server_private_key = parameters.generate_private_key()
        
        # 2. Server sends the public parameters and its public key to the client.
        #    We convert them to bytes (serialize) to send them over the network.
        params_bytes = parameters.parameter_bytes(serialization.Encoding.PEM, serialization.ParameterFormat.PKCS3)
        server_public_key_bytes = server_private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        client_socket.send(params_bytes)
        client_socket.send(server_public_key_bytes)
        print("   -> Sent DH parameters and server's public key to client.")

        # 3. Server receives the client's public key.
        client_public_key_bytes = client_socket.recv(2048)
        client_public_key = serialization.load_pem_public_key(client_public_key_bytes)
        print("   <- Received client's public key.")

        # 4. Server computes the shared secret.
        shared_key = server_private_key.exchange(client_public_key)

        # 5. VERY IMPORTANT: Derive a final key from the shared secret.
        #    The raw result of DH is not suitable for direct use as an encryption key.
        #    We use a Key Derivation Function (HKDF) to create a strong 32-byte key.
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'handshake_data',
        ).derive(shared_key)
        
        print(f"✅ Secure shared key established!\n")
        # Now, `derived_key` can be used for AES encryption in Phase 3.

        # ======================================================================
        # --- PHASE 1: COMMUNICATION LOOP (Now secure in theory) ---
        # ======================================================================

        while True:
            data = client_socket.recv(1024)
            if not data:
                break
            # In Phase 3, we will decrypt this data using the derived_key.
            print(f"Client (encrypted): '{data.hex()}'") # Print as hex for now
            
            if data.decode('utf-8', errors='ignore').strip().lower() == 'exit':
                break

            # In Phase 3, we will encrypt this message.
            client_socket.send(b"Message received")

    except Exception as e:
        print(f"An error occurred: {e}")
    finally:
        print(f"🔌 Connection with {addr} has been closed.")
        client_socket.close()
