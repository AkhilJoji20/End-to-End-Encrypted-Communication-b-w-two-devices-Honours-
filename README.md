# Secure Python Chat Application 🔐

This is a secure, command-line chat application built in Python that demonstrates a complete end-to-end encryption (E2EE) pipeline. Messages sent between the client and server are encrypted and can only be read by the intended recipient.

## Features

* **End-to-End Encryption:** Messages are encrypted on the sender's device and can only be decrypted by the recipient's device.
* **Secure Key Exchange:** Uses the **Diffie-Hellman (DH)** algorithm to allow the client and server to securely establish a shared secret key over an insecure channel.
* **Modern Symmetric Encryption:** Employs **AES-GCM** to encrypt all chat messages. This provides both confidentiality (secrecy) and authenticity (proving the message hasn't been tampered with).
* **Client-Server Architecture:** Built on a simple and robust TCP socket connection model.

## How It Works

The security of this application is established in three phases:

1.  **Connection:** A standard TCP socket connection is established between the client and the server.
2.  **Key Exchange:** Immediately after connecting, the client and server perform a Diffie-Hellman handshake. They securely agree on a shared secret key without ever exposing it to a potential eavesdropper.
3.  **Secure Communication:** All subsequent messages are encrypted and authenticated using AES-GCM with the shared key. Each message uses a unique nonce, ensuring strong cryptographic security.

## How to Use

1.  **Prerequisites:**
    * Python 3
    * The `cryptography` library (`pip install cryptography`)

2.  **Start the Server:**
    * On your server machine, run the following command in a terminal:
        ```bash
        python server.py
        ```
    * The server will start and listen for incoming connections.

3.  **Configure and Start the Client:**
    * On the server machine, find its **local IP address** (using `ipconfig` on Windows or `ifconfig` / `ip a` on macOS/Linux).
    * Open the `client.py` file and change the `host` variable to the server's local IP address.
    * On a second machine (or in a second terminal on the same machine), run the client:
        ```bash
        python client.py
        ```
    * You can now start sending end-to-end encrypted messages!

## Technologies Used

* **Python 3**
* **Cryptography Library:** For Diffie-Hellman and AES-GCM implementations.
* **Socket Module:** For low-level networking.
