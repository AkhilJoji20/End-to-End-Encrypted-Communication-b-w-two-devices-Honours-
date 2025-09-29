import socket
import os
import threading
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

HEADER_SIZE = 256
FILE_SIGNAL = b"!!FILE_TRANSFER_INITIATED!!"

def receive_file(sock):
    try:
        header_data = sock.recv(HEADER_SIZE).decode('utf-8').strip()
        filename, filesize = header_data.split("<SEPARATOR>")
        filesize = int(filesize)
        
        print(f"\n<- [File Transfer] Incoming file: {filename} ({filesize} bytes). Receiving...")
        with open(f"received_{filename}", "wb") as f:
            bytes_received = 0
            while bytes_received < filesize:
                chunk = sock.recv(4096)
                if not chunk: break
                f.write(chunk)
                bytes_received += len(chunk)
        print(f"<- [File Transfer] File '{filename}' received successfully!")
    except Exception as e:
        print(f"Error receiving file: {e}")

def receive_messages(sock, aes):
    while True:
        try:
            data_chunk = sock.recv(4096)
            if not data_chunk: break
            
            if data_chunk.startswith(FILE_SIGNAL):
                 receive_file(sock)
            else:
                try:
                    nonce = data_chunk[:12]
                    ciphertext = data_chunk[12:]
                    print("\n<- Received new data, decrypting...")
                    plaintext = aes.decrypt(nonce, ciphertext, None)
                    print(f"Decrypted message: '{plaintext.decode('utf-8')}'")
                except InvalidTag:
                    print("<- Decryption failed (InvalidTag). A message fragment may have been received.")
                    continue
        except (ConnectionResetError, ConnectionAbortedError):
            print("🔌 Server has disconnected.")
            break
    os._exit(0)

host = 'IPV4 Address of Host' # IMPORTANT: Change to server's LOCAL IP
port = 9999
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

try:
    print(f"Attempting to connect to {host}:{port}...")
    client_socket.connect((host, port))
    print("✅ Successfully connected to the server.")

    params_bytes = client_socket.recv(2048)
    server_public_key_bytes = client_socket.recv(2048)
    parameters = serialization.load_pem_parameters(params_bytes)
    server_public_key = serialization.load_pem_public_key(server_public_key_bytes)
    client_private_key = parameters.generate_private_key()
    client_public_key_bytes = client_private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)
    client_socket.sendall(client_public_key_bytes)
    shared_key = client_private_key.exchange(server_public_key)
    derived_key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b'handshake_data').derive(shared_key)
    print(f"✅ Secure shared key established!")
    print(f"   AES-256 Key (in hex): {derived_key.hex()}\n")
    aesgcm = AESGCM(derived_key)
    
    receive_thread = threading.Thread(target=receive_messages, args=(client_socket, aesgcm))
    receive_thread.daemon = True
    receive_thread.start()

    print("Chat started. To send a file, type 'upload <filepath>'. Type 'exit' to quit.")
    while True:
        message_to_send = input()
        if message_to_send.startswith('upload '):
            try:
                filepath = message_to_send.split(' ', 1)[1].strip('"')
                if not os.path.exists(filepath):
                    print(f"File not found: {filepath}")
                    continue
                
                filename = os.path.basename(filepath)
                filesize = os.path.getsize(filepath)

                client_socket.sendall(FILE_SIGNAL)
                metadata = f"{filename}<SEPARATOR>{filesize}".encode('utf-8')
                metadata += b' ' * (HEADER_SIZE - len(metadata))
                client_socket.sendall(metadata)

                print(f"-> [File Transfer] Sending {filename} ({filesize} bytes)...")
                with open(filepath, "rb") as f:
                    while True:
                        bytes_read = f.read(4096)
                        if not bytes_read: break
                        client_socket.sendall(bytes_read)
                print("-> [File Transfer] File sent successfully!")
            except Exception as e:
                print(f"File sending failed: {e}")
        else:
            print("-> Encrypting your message...")
            nonce = os.urandom(12)
            plaintext = message_to_send.encode('utf-8')
            ciphertext = aesgcm.encrypt(nonce, plaintext, None)
            
            # Combine nonce and ciphertext into a single message
            full_message = nonce + ciphertext
            client_socket.sendall(full_message)

            print("-> Message sent!")
            if message_to_send.strip().lower() == 'exit':
                os._exit(0)

except Exception as e:
    print(f"An error occurred: {e}")
finally:
    print("🔌 Disconnecting from the server.")
    client_socket.close()
