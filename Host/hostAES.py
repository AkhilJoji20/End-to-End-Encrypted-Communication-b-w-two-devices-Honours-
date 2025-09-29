import socket
import os
import threading
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag
import sys

HEADER_SIZE = 256
FILE_SIGNAL = b"!!FILE_TRANSFER_INITIATED!!"

# --- File Handling ---
def receive_file(sock):
    """Handles the reception of a file from the client."""
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

# --- Message Handling ---
def receive_messages(sock, aes):
    """Continuously listens for and decrypts messages from the client."""
    while True:
        try:
            data_chunk = sock.recv(4096)
            if not data_chunk:
                print("\n<- Client has disconnected.")
                break

            if data_chunk.startswith(FILE_SIGNAL):
                receive_file(sock)
            else:
                try:
                    nonce = data_chunk[:12]
                    ciphertext = data_chunk[12:]
                    print("\n<- Received new data, decrypting...")
                    plaintext = aes.decrypt(nonce, ciphertext, None)
                    message = plaintext.decode('utf-8')
                    print(f"Decrypted message: '{message}'")
                    if message.strip().lower() == 'exit':
                        print("<- Client initiated shutdown. Closing connection.")
                        sock.close()
                        return # Exit the thread
                except InvalidTag:
                    print("<- Decryption failed (InvalidTag). A message fragment may have been received.")
                    continue
        except (ConnectionResetError, ConnectionAbortedError):
            print("<- Client connection was lost.")
            break
        except Exception as e:
            print(f"An error occurred in receive_messages: {e}")
            break
    
def send_messages(sock, aes):
    """Handles user input and sends encrypted messages to the client."""
    print("\nChat started. To send a file, type 'upload <filepath>'. Type 'exit' to quit.")
    while True:
        message_to_send = input()
        if not message_to_send: continue

        if message_to_send.startswith('upload '):
            try:
                filepath = message_to_send.split(' ', 1)[1].strip().strip('"')
                if not os.path.exists(filepath):
                    print(f"-> [Error] File not found: {filepath}")
                    continue
                
                filename = os.path.basename(filepath)
                filesize = os.path.getsize(filepath)

                sock.sendall(FILE_SIGNAL)
                metadata = f"{filename}<SEPARATOR>{filesize}".encode('utf-8')
                metadata += b' ' * (HEADER_SIZE - len(metadata))
                sock.sendall(metadata)

                print(f"-> [File Transfer] Sending {filename} ({filesize} bytes)...")
                with open(filepath, "rb") as f:
                    while True:
                        bytes_read = f.read(4096)
                        if not bytes_read: break
                        sock.sendall(bytes_read)
                print("-> [File Transfer] File sent successfully!")
            except Exception as e:
                print(f"-> [Error] File sending failed: {e}")
        else:
            try:
                print("-> Encrypting your message...")
                nonce = os.urandom(12)
                plaintext = message_to_send.encode('utf-8')
                ciphertext = aes.encrypt(nonce, plaintext, None)
                
                full_message = nonce + ciphertext
                sock.sendall(full_message)
                
                print("-> Message sent!")
                if message_to_send.strip().lower() == 'exit':
                    print("-> Shutdown initiated. Closing connection.")
                    sock.close()
                    return # Exit the thread
            except Exception as e:
                print(f"-> [Error] Failed to send message: {e}")
                break

def handle_client(client_socket, addr):
    """Manages a single client connection, including key exchange and threading."""
    print(f"🤝 Got a new connection from {addr}")
    try:
        # --- Diffie-Hellman Key Exchange ---
        print("[Key Exchange] Generating DH parameters...")
        parameters = dh.generate_parameters(generator=2, key_size=2048)
        server_private_key = parameters.generate_private_key()
        
        params_bytes = parameters.parameter_bytes(serialization.Encoding.PEM, serialization.ParameterFormat.PKCS3)
        server_public_key_bytes = server_private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)
        
        print("[Key Exchange] Sending parameters and public key to client...")
        client_socket.sendall(params_bytes)
        client_socket.sendall(server_public_key_bytes)
        
        print("[Key Exchange] Receiving client's public key...")
        client_public_key_bytes = client_socket.recv(2048)
        client_public_key = serialization.load_pem_public_key(client_public_key_bytes)
        
        shared_key = server_private_key.exchange(client_public_key)
        derived_key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b'handshake_data').derive(shared_key)
        
        print(f"✅ Secure shared key established with {addr}!")
        print(f"   AES-256 Key (in hex): {derived_key.hex()}")
        aesgcm = AESGCM(derived_key)

        # --- Start Communication Threads ---
        receive_thread = threading.Thread(target=receive_messages, args=(client_socket, aesgcm))
        send_thread = threading.Thread(target=send_messages, args=(client_socket, aesgcm))
        
        receive_thread.daemon = True
        send_thread.daemon = True
        
        receive_thread.start()
        send_thread.start()
        
        # Wait for threads to finish (e.g., on 'exit' command)
        receive_thread.join()
        send_thread.join()

    except Exception as e:
        print(f"An error occurred with client {addr}: {e}")
    finally:
        print(f"🔌 Connection with {addr} has been closed.")
        client_socket.close()

def main():
    host = '0.0.0.0' # Listen on all available network interfaces
    port = 9999
    
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((host, port))
    server_socket.listen()
    print(f"✅ Server is listening for connections on port {port}")

    try:
        while True:
            client_socket, addr = server_socket.accept()
            # Start a new thread for each client to handle multiple connections
            client_handler_thread = threading.Thread(target=handle_client, args=(client_socket, addr))
            client_handler_thread.daemon = True
            client_handler_thread.start()
    except KeyboardInterrupt:
        print("\nServer is shutting down.")
    finally:
        server_socket.close()
        sys.exit(0)

if __name__ == "__main__":
    main()
