import socket

# --- 1. Setup the Server ---
# Use '0.0.0.0' to allow connections from any network interface
host = '0.0.0.0'
port = 9999

# Create and configure the server socket
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind((host, port))
server_socket.listen()
print(f"✅ Server is listening for connections on port {port}")

# --- 2. Main Server Loop to Accept New Clients ---
while True:
    # Wait for a new client to connect
    client_socket, addr = server_socket.accept()
    print(f"🤝 Got a new connection from {addr}")

    # --- 3. Communication Loop with the Connected Client ---
    while True:
        try:
            # Wait to receive a message from the client
            data = client_socket.recv(1024)
            if not data:
                # If no data is received, the client has disconnected
                break

            received_message = data.decode('utf-8')
            print(f"Client ({addr}) says: '{received_message}'")

            # If the client wants to exit, close the loop for this client
            if received_message.strip().lower() == 'exit':
                break
            
            # Send a response back to the client
            message_to_client = f"Server received: {received_message}"
            client_socket.send(message_to_client.encode('utf-8'))

        except ConnectionResetError:
            print(f"⚠️  Client {addr} connection was forcibly closed.")
            break

    # --- 4. Close Client Connection and Wait for a New One ---
    print(f"🔌 Connection with {addr} has been closed.")
    client_socket.close()
