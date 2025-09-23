import socket

# --- 1. Setup the Client ---
# IMPORTANT: Replace 'SERVER_IP_ADDRESS' with the actual local IP of the server.
host = 'host ipv4 add'
port = 9999

# Create the client socket
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

try:
    # --- 2. Connect to the Server ---
    print(f"Attempting to connect to {host}:{port}...")
    client_socket.connect((host, port))
    print("✅ Successfully connected to the server. Type 'exit' to quit.")

    # --- 3. Communication Loop ---
    while True:
        # Get user input
        message_to_server = input("You: ")

        # Send the message to the server
        client_socket.send(message_to_server.encode('utf-8'))

        # Check if the user wants to exit
        if message_to_server.strip().lower() == 'exit':
            break

        # Receive the server's response
        data = client_socket.recv(1024)
        received_message = data.decode('utf-8')
        print(f"Server says: '{received_message}'")

except ConnectionRefusedError:
    print(f"❌ Connection failed. Ensure the server is running at {host} and the IP is correct.")
except Exception as e:
    print(f"An error occurred: {e}")
finally:
    # --- 4. Close the Connection ---
    print("🔌 Disconnecting from the server.")
    client_socket.close()
