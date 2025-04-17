"""
Author: Tomer Meskin
Date: 21/03/2025

Description: RSA class that allows encryption and decryption of
data using no RSA library, supports external public keys.
"""

import logging
import os
import json
import struct
import time
import socket

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


logger = setup_logger('RSA', os.path.join(FILE_PATH_LOGS_FOLDER, 'Protocol.log'))


class Protocol:
    def __init__(self, aes, rsa=None):
        """
        Initializes the protocol with an AES encryption object and an optional RSA instance.
        :param aes: An instance of your AES class (with key already set).
        :param rsa: An instance of your RSA class for key exchange, optional.
        """
        self.aes = aes
        self.rsa = rsa

    @staticmethod
    def construct_message(msg_type, sender, receiver, data):
        """
        Builds a message dictionary with consistent fields.
        :param msg_type: Type of the message (e.g., 'login', 'message', etc.)
        :param sender: The sender's ID
        :param receiver: The receiver's ID
        :param data: The actual data content (string)
        :return: Message dictionary
        """
        return {
            "type": msg_type,
            "from": sender,
            "to": receiver,
            "timestamp": time.strftime('%Y-%m-%dT%H:%M:%S'),
            "data": data
        }

    def send_message(self, sock: socket.socket, message_dict: dict):
        """
        Encrypts and sends a message over a socket with a length prefix.
        :param sock: The connected socket
        :param message_dict: The message dictionary to send
        """
        json_str = json.dumps(message_dict)
        encrypted_str = self.aes.encrypt(json_str)  # base64-encoded
        encrypted_bytes = encrypted_str.encode()

        msg_len = struct.pack('>I', len(encrypted_bytes))
        sock.sendall(msg_len + encrypted_bytes)

    def receive_message(self, sock: socket.socket):
        """
        Receives and decrypts a message from the socket.
        :param sock: The connected socket
        :return: Decrypted message dictionary
        """
        raw_len = self._recv_exact(sock, 4)
        if not raw_len:
            raise ConnectionError("Connection closed while reading message length.")

        msg_len = struct.unpack('>I', raw_len)[0]
        encrypted_data = self._recv_exact(sock, msg_len)
        if not encrypted_data:
            raise ConnectionError("Connection closed while reading message data.")

        return self.unpack_message(encrypted_data)

    def unpack_message(self, encrypted_bytes: bytes):
        """
        Decrypts and parses the message into a dictionary.
        :param encrypted_bytes: Encrypted message (base64 string, encoded to bytes)
        :return: Decrypted message dictionary
        """
        encrypted_str = encrypted_bytes.decode()
        decrypted_json = self.aes.decrypt(encrypted_str)
        return json.loads(decrypted_json)

    def send_key_transaction(self, sock: socket.socket, aes_key: bytes):
        """
        Encrypt and send the AES key to the client/server using RSA encryption.
        :param sock: The connected socket
        :param aes_key: The AES key to be sent.
        """
        encrypted_aes_key = self.rsa.encrypt(aes_key.decode())  # Encrypt the AES key using RSA
        key_message = self.construct_message('key_exchange', 'server', 'client', encrypted_aes_key)
        self.send_message(sock, key_message)

    def receive_key_transaction(self, sock: socket.socket):
        """
        Receive and decrypt an AES key for communication using RSA.
        :param sock: The connected socket
        :return: The decrypted AES key (bytes)
        """
        key_message = self.receive_message(sock)
        encrypted_aes_key = key_message['data']
        aes_key = self.rsa.decrypt(encrypted_aes_key)  # Decrypt the AES key using RSA
        return aes_key.encode()  # Return the decrypted AES key as bytes

    @staticmethod
    def _recv_exact(sock, n):
        """
        Helper function to receive exactly n bytes.
        :param sock: Socket to read from
        :param n: Number of bytes to read
        :return: Received bytes or None if connection drops
        """
        data = b''
        while len(data) < n:
            chunk = sock.recv(n - len(data))
            if not chunk:
                return None
            data += chunk
        return data
