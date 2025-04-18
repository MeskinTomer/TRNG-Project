"""
Author: Tomer Meskin
Date: 17/04/2025

Description: Client
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


logger = setup_logger('Client', os.path.join(FILE_PATH_LOGS_FOLDER, 'Client.log'))


if __name__ == '__main__':
    gen = Generator()
    rsa = RSA(gen)
    rsa.generate_keys()
    aes = AES(gen)
    aes.generate_key("my_secure_password")
    protocol = Protocol(aes, rsa)

    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(('localhost', 8080))

    public_key_message = protocol.receive_public_rsa_key(client_socket)
    print(public_key_message)

    protocol.send_aes_key(client_socket, 'Client', public_key_message['data'])
    print(protocol.aes.key)
