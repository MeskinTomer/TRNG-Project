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
    def __init__(self):
        """
        Initializes the protocol with AES and RSA instances
        """
        gen = Generator()

        self.aes = AES(gen)
        self.rsa = RSA(gen)

        logger.info('Instance created')

    @staticmethod
    def construct_message(msg_type, sender, target, data):
        """
        Builds a message dictionary with consistent fields.
        :param msg_type: Type of the message (e.g., 'login', 'message', etc.)
        :param sender: The sender's ID
        :param target: The target's ID
        :param data: The actual data content (string)
        :return: Message dictionary
        """
        return {
            "type": msg_type,
            "from": sender,
            "to": target,
            "timestamp": time.strftime('%Y-%m-%dT%H:%M:%S'),
            "data": data
        }

    def send_message(self, sock: socket.socket, sender, target, text):
        """
        Encrypts and sends a message over a socket with a length prefix.
        :param sock: The connected socket
        :param sender: The sender's ID
        :param target: The target's ID
        :param text: The actual message content (string)
        """

        encrypted_text = self.aes.encrypt(text)
        message_dict = self.construct_message('message', sender, target, encrypted_text)

        json_str = json.dumps(message_dict)
        json_bytes = json_str.encode()

        msg_len = struct.pack('>I', len(json_bytes))
        sock.sendall(msg_len + json_bytes)

        logger.debug(f'Sent message: {message_dict['data']}')

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
        Receives, decodes, and loads a message from the socket.
        :param sock: The connected socket
        :return: Decrypted message dictionary
        """
        raw_len = self._recv_exact(sock, 4)
        if not raw_len:
            raise ConnectionError("Connection closed while reading message length.")

        msg_len = struct.unpack('>I', raw_len)[0]
        received_data = self._recv_exact(sock, msg_len)
        if not received_data:
            raise ConnectionError("Connection closed while reading message data.")

        data_str = received_data.decode()
        message_dict = json.loads(data_str)

        logger.debug(f'Received message: {message_dict}')
        return message_dict

    def decrypt_message(self, message_dict):
        """
        Decrypts the data part of the message dictionary.
        :param message_dict: Message dictionary
        :return: Decrypted message text
        """
        encrypted_str = message_dict['data']
        decrypted_str = self.aes.decrypt(encrypted_str)
        return decrypted_str

    def send_public_rsa_key(self, sock: socket.socket, sender, target):
        """
        Sends the public RSA key of the sender
        :param sock: The connected socket
        :param sender: Sender identification
        :param target: Target identification
        """
        message_dict = self.construct_message('public key', sender, target, self.rsa.public_key)

        # Convert message into json and convert it into bytes
        json_str = json.dumps(message_dict)
        message_bytes = json_str.encode()

        msg_len = struct.pack('>I', len(message_bytes))

        logger.debug('Sent public RSA key')
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

        logger.debug('Received public RSA key')
        return json.loads(json_str)

    def send_aes_key(self, sock: socket.socket, sender, target, external_rsa_public_key):
        """
        Sends the AES key, encrypted with the external RSA public key
        (Not sent with json due to RSA byte limit)
        :param sock: The connected socket
        :param sender: Sender identification
        :param external_rsa_public_key: Public RSA key for encryption
        """
        key_b64 = base64.b64encode(self.aes.key).decode('utf-8')

        # Encrypts the AES key and add metadata to it
        encrypted_int = self.rsa.encrypt(key_b64, external_rsa_public_key)
        metadata_str = f'{sender}!{target}!'
        message_str = metadata_str + str(encrypted_int)

        # Encode final message and send it
        message_bytes = str(message_str).encode()
        msg_len = struct.pack('>I', len(message_bytes))

        logger.debug('Sent AES key')
        sock.sendall(msg_len + message_bytes)

    def receive_aes_message(self, sock: socket.socket):
        """
        Receives the agreed upon AES key message
        :param sock: The connected socket
        :return: sender ID, target ID, encrypted AES key
        """
        raw_len = self._recv_exact(sock, 4)
        if not raw_len:
            raise ConnectionError("Connection closed while reading message length.")

        msg_len = struct.unpack('>I', raw_len)[0]
        message_bytes = self._recv_exact(sock, msg_len)
        if not message_bytes:
            raise ConnectionError("Connection closed while reading message data.")

        sender, target, encrypted_str = message_bytes.decode().split('!')
        return sender, target, encrypted_str

    def decrypt_aes_key(self, encrypted_str):
        """
        Decrypts RSA encrypted AES key
        :param encrypted_str: The encrypted str key
        :return: sender ID, target ID, encrypted AES key
        """
        decrypted_bytes = self.rsa.decrypt(int(encrypted_str))

        aes_key_b64 = decrypted_bytes.decode('utf-8')
        aes_key = base64.b64decode(aes_key_b64)

        return aes_key

    def send_clients_amount(self, sock: socket.socket, sender, target, num):
        message_dict = self.construct_message('clients amount', sender, target, num)

        # Convert message into json and convert it into bytes
        json_str = json.dumps(message_dict)
        message_bytes = json_str.encode()

        msg_len = struct.pack('>I', len(message_bytes))

        logger.debug('Sent clients amount')
        sock.sendall(msg_len + message_bytes)

    def receive_clients_amount(self, sock: socket.socket):
        raw_len = self._recv_exact(sock, 4)
        if not raw_len:
            raise ConnectionError("Connection closed while reading message length.")

        msg_len = struct.unpack('>I', raw_len)[0]
        json_bytes = self._recv_exact(sock, msg_len)
        if not json_bytes:
            raise ConnectionError("Connection closed while reading message data.")

        json_str = json_bytes.decode()

        logger.debug('Received clients amount')
        return json.loads(json_str)

    def __repr__(self):
        return "<Protocol instance>"


if __name__ == '__main__':

    protocol = Protocol()
    protocol.aes.generate_key("my_secure_password")
    # message = protocol.construct_message('message', 'Tomer', 'Hello World!')






