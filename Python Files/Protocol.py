"""
Author: Tomer Meskin
Date: 17/04/2025

Description: Protocol
"""

import socket
import json
import time
import struct
import logging
import os
from RSA import RSA
from AES import AES
from Generator import Generator
import base64

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


logger = setup_logger('Protocol', os.path.join(FILE_PATH_LOGS_FOLDER, 'Protocol.log'))


class Protocol:
    def __init__(self, aes, rsa):
        """
        Initializes the protocol with an AES encryption object and an optional RSA instance.
        :param aes: An instance of your AES class (with key already set).
        :param rsa: An instance of your RSA class for key exchange, optional.
        """
        self.aes = aes
        self.rsa = rsa

    @staticmethod
    def construct_message(msg_type, sender, data):
        """
        Builds a message dictionary with consistent fields.
        :param msg_type: Type of the message (e.g., 'login', 'message', etc.)
        :param sender: The sender's ID
        :param data: The actual data content (string)
        :return: Message dictionary
        """
        return {
            "type": msg_type,
            "from": sender,
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

    def send_public_rsa_key(self, sock: socket.socket, sender):
        """
        Sends the public RSA key of the sender
        :param sock: The connected socket
        :param sender: Sender identification
        """
        message_dict = self.construct_message('public key', sender, self.rsa.public_key)

        # Convert message into json and convert it into bytes
        json_str = json.dumps(message_dict)
        message_bytes = json_str.encode()

        msg_len = struct.pack('>I', len(message_bytes))
        sock.sendall(msg_len + message_bytes)

    def receive_public_rsa_key(self, sock: socket.socket):
        """
        Receives the public RSA key from socket
        :param sock: The connected socket
        :return: external public RSA key
        """
        raw_len = self._recv_exact(sock, 4)
        if not raw_len:
            raise ConnectionError("Connection closed while reading message length.")

        msg_len = struct.unpack('>I', raw_len)[0]
        json_bytes = self._recv_exact(sock, msg_len)
        if not json_bytes:
            raise ConnectionError("Connection closed while reading message data.")

        json_str = json_bytes.decode()
        return json.loads(json_str)

    def send_aes_key(self, sock: socket.socket, sender, external_rsa_public_key):
        """
        Sends the AES key, encrypted with the external RSA public key
        (Not sent with json due to RSA byte limit)
        :param sock: The connected socket
        :param sender: Sender identification
        :param external_rsa_public_key: Public RSA key for encryption
        """
        key_b64 = base64.b64encode(self.aes.key).decode('utf-8')

        # Encrypts the AES key and converts it into bytes
        encrypted_int = self.rsa.encrypt(key_b64, external_rsa_public_key)
        encrypted_bytes = str(encrypted_int).encode()

        msg_len = struct.pack('>I', len(encrypted_bytes))
        sock.sendall(msg_len + encrypted_bytes)

    def receive_aes_key(self, sock: socket.socket):
        """
        Receives the agreed upon AES key, while RSA decrypting it
        :param sock: The connected socket
        :return: Decrypted message dictionary
        """
        raw_len = self._recv_exact(sock, 4)
        if not raw_len:
            raise ConnectionError("Connection closed while reading message length.")

        msg_len = struct.unpack('>I', raw_len)[0]
        encrypted_bytes = self._recv_exact(sock, msg_len)
        if not encrypted_bytes:
            raise ConnectionError("Connection closed while reading message data.")

        # Decodes the bytes into an str, and then RSA decrypts it
        encrypted_str = encrypted_bytes.decode()
        decrypted_bytes = self.rsa.decrypt(int(encrypted_str))

        # Extracts the AES key from the decrypted data
        aes_key_b64 = decrypted_bytes.decode('utf-8')
        aes_key = base64.b64decode(aes_key_b64)

        return aes_key


if __name__ == '__main__':
    gen = Generator()
    rsa = RSA(gen)
    aes = AES(gen)
    aes.generate_key("my_secure_password")
    protocol = Protocol(aes, rsa)

    # message = protocol.construct_message('message', 'Tomer', 'Hello World!')






