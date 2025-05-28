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

logger = None
MAX_REASONABLE_LENGTH = 10000  # Max bytes for a single message, including RSA-encrypted keys


class Protocol:
    def __init__(self, passed_logger):
        global logger
        logger = passed_logger
        logger.info('Initializing Protocol instance')
        gen = Generator()
        self.aes = AES(gen)
        self.rsa = RSA(gen)
        logger.info('Protocol instance created successfully')

    @staticmethod
    def construct_message(msg_type, sender, target, data):
        logger.debug(f'Constructing message | Type: {msg_type}, Sender: {sender}, Target: {target}')
        return {
            "type": msg_type,
            "sender": sender,
            "target": target,
            "timestamp": time.strftime('%Y-%m-%dT%H:%M:%S'),
            "data": data
        }

    def send_message(self, sock: socket.socket, sender, target, type, text, is_transfer=False):
        logger.info(f'Sending message | Type: {type}, Sender: {sender}, Target: {target}')
        encrypted_text = text if is_transfer else self.aes.encrypt(text)
        message_dict = self.construct_message(type, sender, target, encrypted_text)

        json_bytes = json.dumps(message_dict).encode()
        msg_len = struct.pack('>I', len(json_bytes))

        sock.sendall(msg_len + json_bytes)
        logger.debug(f'Message sent successfully | Length: {len(json_bytes)} bytes')

    @staticmethod
    def _recv_exact(sock, n):
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

    def receive_message(self, sock: socket.socket):
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
        logger.debug(f'Received message | Type: {message_dict.get("type")}, Sender: {message_dict.get("sender")}')
        return message_dict

    def decrypt_message(self, message_dict):
        logger.debug(f'Decrypting message from {message_dict["sender"]}')
        decrypted_str = self.aes.decrypt(message_dict['data'])
        logger.debug(f'Message decrypted successfully: {decrypted_str}')
        return decrypted_str

    def send_public_rsa_key(self, sock: socket.socket, sender, target):
        logger.info(f'Sending public RSA key | Sender: {sender}, Target: {target}')
        message_dict = self.construct_message('public key', sender, target, self.rsa.public_key)

        message_bytes = json.dumps(message_dict).encode()
        msg_len = struct.pack('>I', len(message_bytes))

        sock.sendall(msg_len + message_bytes)
        logger.debug(f'Public RSA key sent successfully')

    def receive_public_rsa_key(self, sock: socket.socket):
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
        logger.debug(f'Public RSA key received | From: {public_key_data.get("sender")} | Target: {public_key_data.get("target")}')
        return public_key_data

    def send_aes_key(self, sock: socket.socket, sender, target, external_rsa_public_key=None, is_transfer=False, transfer_key=None):
        logger.info(f'Sending AES key | Sender: {sender}, Target: {target}, Transfer: {is_transfer}')
        if not is_transfer:
            key_b64 = base64.b64encode(self.aes.key).decode('utf-8')
            encrypted_int = self.rsa.encrypt(key_b64, external_rsa_public_key)
        else:
            encrypted_int = transfer_key

        metadata_str = f'{sender}!{target}!'
        message_str = metadata_str + str(encrypted_int)
        message_bytes = message_str.encode()
        msg_len = struct.pack('>I', len(message_bytes))

        logger.critical(f'msg len: {msg_len} | aes_key: {encrypted_int}')
        sock.sendall(msg_len + message_bytes)
        logger.debug(f'AES key sent successfully | Encrypted Int Length: {len(str(encrypted_int))} digits')

    def receive_aes_message(self, sock: socket.socket):
        logger.info('Receiving AES key message')
        raw_len = self._recv_exact(sock, 4)
        if not raw_len:
            raise ConnectionError("Connection closed while reading message length.")

        logger.debug(f"Raw length bytes: {list(raw_len)}")
        msg_len = struct.unpack('>I', raw_len)[0]
        if msg_len > MAX_REASONABLE_LENGTH:
            logger.critical(f"Unrealistic AES message length received: {msg_len}")
            raise ValueError(f"Message length too large: {msg_len}")

        message_bytes = self._recv_exact(sock, msg_len)
        if not message_bytes:
            raise ConnectionError("Connection closed while reading message data.")

        try:
            parts = message_bytes.decode().split('!')
            if len(parts) != 3:
                raise ValueError("Incorrect format. Expected sender!target!encrypted_int")
            sender, target, encrypted_str = parts
        except Exception as e:
            logger.critical(f"Failed to parse AES message: {e}")
            raise ConnectionError("Corrupted AES message received")

        logger.debug(f'Received AES key message | Sender: {sender}, Target: {target}')
        return sender, target, encrypted_str

    def decrypt_aes_key(self, encrypted_str):
        logger.info('Decrypting received AES key')
        decrypted_bytes = self.rsa.decrypt(int(encrypted_str))
        aes_key_b64 = decrypted_bytes.decode('utf-8')
        aes_key = base64.b64decode(aes_key_b64)
        logger.debug('AES key decrypted successfully')
        return aes_key

    def send_clients_amount(self, sock: socket.socket, sender, target, num):
        logger.info(f'Sending clients amount: {num} | Sender: {sender}, Target: {target}')
        message_dict = self.construct_message('clients amount', sender, target, str(num))

        message_bytes = json.dumps(message_dict).encode()
        msg_len = struct.pack('>I', len(message_bytes))

        sock.sendall(msg_len + message_bytes)
        logger.debug('Clients amount sent successfully')

    def receive_clients_amount(self, sock: socket.socket):
        logger.info('Receiving clients amount')
        raw_len = self._recv_exact(sock, 4)
        if not raw_len:
            raise ConnectionError("Connection closed while reading message length.")

        msg_len = struct.unpack('>I', raw_len)[0]
        if msg_len > MAX_REASONABLE_LENGTH:
            raise ValueError(f"Message length too large: {msg_len}")

        json_bytes = self._recv_exact(sock, msg_len)
        if not json_bytes:
            raise ConnectionError("Connection closed while reading message data.")

        clients_data = json.loads(json_bytes.decode())
        logger.debug(f'Clients amount received: {clients_data.get("data")}')
        return clients_data

    def __repr__(self):
        return "<Protocol instance>"


if __name__ == '__main__':
    protocol = Protocol()
    protocol.aes.generate_key("my_secure_password")