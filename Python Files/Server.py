"""
Author: Tomer Meskin
Date: 17/04/2025

Description: Server
"""

import socket
from RSA import RSA
from AES import AES
from Generator import Generator
from Protocol import Protocol
from DataBase import Database
import logging
import os

FILE_PATH_LOGS_FOLDER = os.path.join(os.path.dirname(__file__), '..', 'Log Files')


def setup_logger(name, log_file, level=logging.DEBUG):
    """Sets up a logger with a file handler."""
    handler = logging.FileHandler(log_file, mode='w')
    formatter = logging.Formatter('%(levelname)s: %(message)s')
    handler.setFormatter(formatter)

    return_logger = logging.getLogger(name)
    return_logger.setLevel(level)
    return_logger.addHandler(handler)
    return return_logger


logger = setup_logger('Server', os.path.join(FILE_PATH_LOGS_FOLDER, 'Server.log'))


class Client:
    def __init__(self):
        self.socket = None
        self.db = Database()
        self.key_ids = []

    def run(self):
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.bind(('localhost', 8080))
        self.socket = server_socket



    def exchange_keys_with_client(self, protocol: Protocol):
        # Send Server's public RSA key
        protocol.send_public_rsa_key(client_socket, 'Server', 'Client')
        print(protocol.rsa.public_key)

        # Receive and set AES key for communication with client
        sender, target, encrypted_key = protocol.receive_aes_message(client_socket)
        aes_key = protocol.decrypt_aes_key(encrypted_key)
        print(sender, target, aes_key)

        protocol.aes.set_key(aes_key)


if __name__ == '__main__':
    protocol = Protocol()
    protocol.rsa.generate_keys()

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('localhost', 8080))
    server_socket.listen(5)

    while True:
        client_socket, client_address = server_socket.accept()

        protocol.send_public_rsa_key(client_socket, 'Server', 'Client')
        print(protocol.rsa.public_key)

        sender, target, encrypted_key = protocol.receive_aes_message(client_socket)
        aes_key = protocol.decrypt_aes_key(encrypted_key)
        print(sender, target, aes_key)

        protocol.aes.set_key(aes_key)

        message_dict = protocol.receive_message(client_socket)
        text = protocol.decrypt_message(message_dict)
        print(text)
        client_socket.close()
