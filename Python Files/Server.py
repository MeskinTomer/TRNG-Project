"""
Author: Tomer Meskin
Date: 17/04/2025

Description: Server
"""

import socket
import json
from RSA import RSA
from AES import AES
from Generator import Generator
from Protocol import Protocol
import datetime
import base64
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


if __name__ == '__main__':
    gen = Generator()
    rsa = RSA(gen)
    rsa.generate_keys()
    aes = AES(gen)

    protocol = Protocol(aes, rsa)

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('localhost', 8080))
    server_socket.listen(5)

    while True:
        client_socket, client_address = server_socket.accept()

        protocol.send_public_rsa_key(client_socket, 'Server')
        print(protocol.rsa.public_key)

        aes_key = protocol.receive_aes_key(client_socket)
        print(aes_key)

        protocol.aes.set_key(aes_key)
    