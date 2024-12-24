#Before you start, make sure to install cryptography by doing the following: Run in Windows CMD: pip install cryptography
#Create a folder named whatever you want and then create 2 .py file in  it, namely client.py and server.py
#This is server.py
#For Further instruction, follow line 85 - 88

from cryptography.fernet import Fernet
import socket
import os
import hashlib
import logging

# Simple authentication check on the server side
def check_credentials(credentials):
    username, password_hash = credentials.split(':')
    stored_username = "Vedish"
    stored_password_hash = hashlib.sha256("CodeAlpha123".encode()).hexdigest()
    return username == stored_username and password_hash == stored_password_hash

# Load the encryption key
def load_key(key_path):
    with open(key_path, 'rb') as key_file:
        return key_file.read()

# Decrypt the file
def decrypt_file(file_path, key):
    fernet = Fernet(key)
    with open(file_path, 'rb') as enc_file:
        encrypted = enc_file.read()
    decrypted = fernet.decrypt(encrypted)
    with open(file_path.replace('.enc', ''), 'wb') as dec_file:
        dec_file.write(decrypted)

# Receive the file from the client
def receive_file(save_path, host, port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((host, port))
        s.listen()
        logging.info(f"Server listening on {host}:{port}")
        conn, addr = s.accept()
        with conn:
            logging.info(f"Connected by {addr}")
            credentials = conn.recv(1024).decode()
            if not check_credentials(credentials):
                logging.error("Authentication failed!")
                conn.sendall(b"Authentication failed!")
                conn.close()
                return

            conn.sendall(b"Authentication successful")
            with open(save_path, 'wb') as file:
                while True:
                    data = conn.recv(1024)
                    if not data:
                        break
                    file.write(data)
            logging.info(f"File {save_path} received successfully.")

if __name__ == "__main__":
    # Configure logging
    logging.basicConfig(filename='server_audit.log', level=logging.INFO, format='%(asctime)s %(message)s')
    logging.info('Server started')

    # Set the directory to save the received encrypted file and the key
    save_dir = r'C:\Users\vedis\Desktop\Code for VS Code\Vedish SecureFileTransfer'
    save_path = os.path.join(save_dir, 'received_file.enc')
    key_path = os.path.join(save_dir, 'filekey.key')
    host = 'localhost'
    port = 65432

    try:
        receive_file(save_path, host, port)

        # Ensure the key file exists before attempting to load it
        if os.path.exists(key_path):
            key = load_key(key_path)
            decrypt_file(save_path, key)
            logging.info(f"Decryption complete. File saved as {save_path.replace('.enc', '')}")
        else:
            logging.error(f"Error: Key file {key_path} not found.")

    except Exception as e:
        logging.error(f"An error occurred: {e}")


#This is the Second task assigned by CODEALPHA to Vedish. Task has been completed. 
#In order for the code to run successfully, follow line 1-4
#The code contains the following information regarding server script for the Secure File Transfer Application 
#Run the server First and then run client in a new open window for client only and you will be asked to provide path of file to be sent.