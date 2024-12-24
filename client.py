#Before you start, make sure to install cryptography by doing the following: Run in Windows CMD: pip install cryptography
#Create a folder named whatever you want and then create 2 .py file in  it, namely client.py and server.py
#This is client.py
#For Further instruction, follow line 80 - 83

from cryptography.fernet import Fernet
import socket
import os
import hashlib
import logging

# Simple username/password authentication
def authenticate(username, password):
    stored_username = "Vedish"
    stored_password_hash = hashlib.sha256("CodeAlpha123".encode()).hexdigest()
    return username == stored_username and hashlib.sha256(password.encode()).hexdigest() == stored_password_hash

# Generate a key for encryption
def generate_key():
    return Fernet.generate_key()

# Encrypt the file
def encrypt_file(file_path, key):
    fernet = Fernet(key)
    with open(file_path, 'rb') as file:
        original = file.read()
    encrypted = fernet.encrypt(original)
    encrypted_file_path = os.path.join(encrypted_file_dir, os.path.basename(file_path) + '.enc')
    with open(encrypted_file_path, 'wb') as encrypted_file:
        encrypted_file.write(encrypted)
    return encrypted_file_path

# Send the encrypted file to the server
def send_file(file_path, host, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((host, port))
            credentials = f"Vedish:{hashlib.sha256('CodeAlpha123'.encode()).hexdigest()}"
            s.sendall(credentials.encode())
            s.recv(1024)  # Wait for server acknowledgment
            with open(file_path, 'rb') as file:
                s.sendall(file.read())
            logging.info(f"File {file_path} sent successfully.")
    except Exception as e:
        logging.error(f"An error occurred while sending the file: {e}")

if __name__ == "__main__":
    # Configure logging
    logging.basicConfig(filename='client_audit.log', level=logging.INFO, format='%(asctime)s %(message)s')
    logging.info('Client started')

    username = input("Enter username: ")
    password = input("Enter password: ")

    if not authenticate(username, password):
        print("Authentication failed!")
        logging.error("Authentication failed.")
        exit(1)

    file_path = input("Enter the path of the file to encrypt and send: ")
    host = 'localhost'  # Server address
    port = 65432        # Server port

    try:
        key = generate_key()
        # Set the directory to save the encrypted file
        encrypted_file_dir = r'C:\Users\vedis\Desktop\Code for VS Code\Vedish SecureFileTransfer'
        encrypted_file_path = encrypt_file(file_path, key)
        send_file(encrypted_file_path, host, port)

        # Save the key to a file (for decryption)
        key_path = os.path.join(encrypted_file_dir, 'filekey.key')
        with open(key_path, 'wb') as key_file:
            key_file.write(key)
        logging.info(f"Encryption key saved to {key_path}")

    except Exception as e:
        logging.error(f"An error occurred: {e}")

#This is the Second task assigned by CODEALPHA to Vedish. Task has been completed. 
#In order for the code to run successfully, follow line 1-4
#The code contains the following information regarding client script for the Secure File Transfer Application 
#Run the server First and then run client in a new open window for client only and you will be asked to provide path of file to be sent.