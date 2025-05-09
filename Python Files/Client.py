"""
Author: Tomer Meskin
Date: 17/04/2025

Description: Client
"""

import socket
from RSA import RSA
from AES import AES
from Generator import Generator
from Protocol import Protocol
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


logger = setup_logger('Client', os.path.join(FILE_PATH_LOGS_FOLDER, 'Client.log'))


class Client:
    def __init__(self):
        gen = Generator
        self.rsa = RSA(gen)
        self.AES = AES(gen)


if __name__ == '__main__':
    protocol = Protocol()
    protocol.aes.generate_key("my_secure_password")

    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(('localhost', 8080))

    public_key_message = protocol.receive_public_rsa_key(client_socket)
    print(public_key_message)

    protocol.send_aes_key(client_socket, 'Client', 'Server', public_key_message['data'])
    print(protocol.aes.key)

    protocol.send_message(client_socket, 'Client', 'Server', 'Hello World!')
