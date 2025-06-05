"""
Author: Tomer Meskin
Date: 17/04/2025

Description: Secure Protocol class using AES and RSA to handle structured and encrypted
message exchange over sockets, including key exchange, encryption, and logging.
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

logger = None
MAX_REASONABLE_LENGTH = 10000


logger = logging.getLogger(__name__)


class Protocol:
    """
    Handles encrypted communication using AES and RSA over sockets.
    Includes methods for sending/receiving messages, AES key transfers, and RSA public key exchange.
    """

    def __init__(self, passed_logger):
        """
        Initializes Protocol with AES, RSA, and a provided logger.

        :param passed_logger: Logger instance for logging activity.
        """
        global logger
        logger = passed_logger
        logger.info('Initializing Protocol instance')
        generator = Generator()
        self.aes = AES(generator)
        self.rsa = RSA(generator)
        logger.info('Protocol instance created successfully')

    @staticmethod
    def construct_message(msg_type: str, sender: str, target: str, data) -> dict:
        """
        Constructs a structured message dictionary.

        :param msg_type: The type of the message (e.g., 'text', 'aes key').
        :param sender: Username of the sender.
        :param target: Username of the intended recipient.
        :param data: The content of the message (encrypted or not).
        :return: A dictionary representing the message.
        """
        logger.debug(f'Constructing message | Type: {msg_type}, Sender: {sender}, Target: {target}')
        return {
            "type": msg_type,
            "sender": sender,
            "target": target,
            "timestamp": time.strftime('%Y-%m-%dT%H:%M:%S'),
            "data": data
        }

    def send_message(self, sock: socket.socket, sender: str, target: str, type: str, text: str,
                     is_transfer: bool = False) -> None:
        """
        Encrypts (unless transfer) and sends a message.

        :param sock: Socket object to send the message through.
        :param sender: Sender's username.
        :param target: Target's username.
        :param type: Message type.
        :param text: Plaintext or already encrypted text.
        :param is_transfer: If True, skips encryption (used for sending AES keys).
        """
        try:
            logger.info(f'Sending message | Type: {type}, Sender: {sender}, Target: {target}')
            encrypted_text = text if is_transfer else self.aes.encrypt(text)
            message_dict = self.construct_message(type, sender, target, encrypted_text)

            json_bytes = json.dumps(message_dict).encode()
            msg_len = struct.pack('>I', len(json_bytes))

            sock.sendall(msg_len + json_bytes)
            logger.debug(f'Message sent successfully | Length: {len(json_bytes)} bytes')
        except Exception as e:
            logger.exception(f"Failed to send message: {e}")

    @staticmethod
    def _recv_exact(sock: socket.socket, n: int):
        """
        Receives exactly n bytes from a socket.

        :param sock: The socket to read from.
        :param n: Number of bytes to receive.
        :return: The received bytes.
        """
        logger.debug(f'Attempting to receive exactly {n} bytes from socket')
        data = b''
        while len(data) < n:
            chunk = sock.recv(n - len(data))
            if not chunk:
                logger.error('Socket connection lost during _recv_exact')
                return None
            data += chunk
        logger.debug(f'Successfully received {n} bytes')
        return data

    def receive_message(self, sock: socket.socket) -> dict:
        """
        Receives and parses a full message.

        :param sock: Socket to receive the message from.
        :return: Parsed message dictionary.
        :raises ConnectionError: If connection closes prematurely.
        :raises ValueError: If message is too large.
        """
        try:
            logger.info('Receiving message from socket')
            raw_len = self._recv_exact(sock, 4)
            if not raw_len:
                raise ConnectionError("Connection closed while reading message length.")

            msg_len = struct.unpack('>I', raw_len)[0]
            if msg_len > MAX_REASONABLE_LENGTH:
                raise ValueError(f"Message length too large: {msg_len}")

            received_data = self._recv_exact(sock, msg_len)
            if not received_data:
                raise ConnectionError("Connection closed while reading message data.")

            message_dict = json.loads(received_data.decode())
            assert isinstance(message_dict, dict)
            logger.debug(f'Received message | Type: {message_dict.get("type")}, Sender: {message_dict.get("sender")}')
            return message_dict
        except Exception as e:
            logger.exception(f"Failed to receive message: {e}")
            raise

    def decrypt_message(self, message_dict: dict) -> str:
        """
        Decrypts the 'data' field from a message dict using AES.

        :param message_dict: The dictionary containing the encrypted message.
        :return: Decrypted plaintext string.
        """
        try:
            logger.debug(f'Decrypting message from {message_dict["sender"]}')
            decrypted_str = self.aes.decrypt(message_dict['data'])
            logger.debug('Message decrypted successfully')
            return decrypted_str
        except Exception as e:
            logger.exception(f"Failed to decrypt message: {e}")
            raise

    def send_public_rsa_key(self, sock: socket.socket, sender: str, target: str) -> None:
        """
        Sends this instance’s public RSA key to the target.

        :param sock: Socket to send the key through.
        :param sender: Sender name.
        :param target: Target name.
        """
        try:
            logger.info(f'Sending public RSA key | Sender: {sender}, Target: {target}')
            message_dict = self.construct_message('public key', sender, target, self.rsa.public_key)
            message_bytes = json.dumps(message_dict).encode()
            msg_len = struct.pack('>I', len(message_bytes))
            sock.sendall(msg_len + message_bytes)
            logger.debug('Public RSA key sent successfully')
        except Exception as e:
            logger.exception(f"Failed to send RSA public key: {e}")

    def receive_public_rsa_key(self, sock: socket.socket) -> dict:
        """
        Receives a public RSA key message from the socket.

        :param sock: Socket to receive the key from.
        :return: Parsed dictionary containing the public key and sender.
        """
        try:
            logger.info('Receiving public RSA key')
            raw_len = self._recv_exact(sock, 4)
            if not raw_len:
                raise ConnectionError("Connection closed while reading message length.")

            msg_len = struct.unpack('>I', raw_len)[0]
            if msg_len > MAX_REASONABLE_LENGTH:
                raise ValueError(f"Message length too large: {msg_len}")

            json_bytes = self._recv_exact(sock, msg_len)
            if not json_bytes:
                raise ConnectionError("Connection closed while reading message data.")

            public_key_data = json.loads(json_bytes.decode())
            logger.debug(f'Public RSA key received | From: {public_key_data.get("sender")} | Target: '
                         f'{public_key_data.get("target")}')
            return public_key_data
        except Exception as e:
            logger.exception(f"Failed to receive RSA public key: {e}")
            raise

    def send_aes_key(self, sock: socket.socket, sender: str, target: str, external_rsa_public_key=None,
                     is_transfer: bool = False, transfer_key: str = None) -> None:
        """
        Sends AES key, encrypted with the recipient's RSA public key.

        :param sock: Socket to send through.
        :param sender: Sender's username.
        :param target: Target's username.
        :param external_rsa_public_key: Target's RSA public key.
        :param is_transfer: True if sending pre-encrypted key.
        :param transfer_key: Already encrypted key (used if is_transfer=True).
        """
        try:
            logger.info(f'Sending AES key | Sender: {sender}, Target: {target}, Transfer: {is_transfer}')
            if not is_transfer:
                key_b64 = base64.b64encode(self.aes.key).decode('utf-8')
                encrypted_int = self.rsa.encrypt(key_b64, external_rsa_public_key)
                encrypted_str = str(encrypted_int)
            else:
                encrypted_str = transfer_key

            message_dict = self.construct_message('aes key', sender, target, encrypted_str)
            message_bytes = json.dumps(message_dict).encode()
            msg_len = struct.pack('>I', len(message_bytes))
            sock.sendall(msg_len + message_bytes)
            logger.debug('AES key sent successfully')
        except Exception as e:
            logger.exception(f"Failed to send AES key: {e}")

    def receive_aes_message(self, sock: socket.socket) -> dict:
        """
        Receives an AES key message.

        :param sock: Socket to receive from.
        :return: Parsed dictionary containing the AES key message.
        """
        try:
            logger.info('Receiving AES key message')
            raw_len = self._recv_exact(sock, 4)
            if not raw_len:
                raise ConnectionError("Connection closed while reading message length.")

            msg_len = struct.unpack('>I', raw_len)[0]
            if msg_len > MAX_REASONABLE_LENGTH:
                raise ValueError(f"Message length too large: {msg_len}")

            message_bytes = self._recv_exact(sock, msg_len)
            if not message_bytes:
                raise ConnectionError("Connection closed while reading message data.")

            aes_key_data = json.loads(message_bytes.decode())
            logger.debug(f'Received AES key message | Type: {aes_key_data.get("type")}, Sender: '
                         f'{aes_key_data.get("sender")}, Target: {aes_key_data.get("target")}')
            return aes_key_data
        except Exception as e:
            logger.exception(f"Failed to receive AES key message: {e}")
            raise

    def decrypt_aes_key(self, encrypted_str: str) -> bytes:
        """
        Decrypts a received AES key using this instance’s private RSA key.

        :param encrypted_str: Encrypted AES key (as string of int).
        :return: Decrypted AES key (bytes).
        """
        try:
            logger.info('Decrypting received AES key')
            decrypted_bytes = self.rsa.decrypt(int(encrypted_str))
            aes_key_b64 = decrypted_bytes.decode('utf-8')
            aes_key = base64.b64decode(aes_key_b64)
            logger.debug('AES key decrypted successfully')
            return aes_key
        except Exception as e:
            logger.exception(f"Failed to decrypt AES key: {e}")
            raise

    def __repr__(self):
        return "<Protocol instance>"
