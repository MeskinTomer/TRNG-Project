"""
Author: Tomer Meskin
Date: 17/04/2025

Description: Server
"""

import socket
import threading

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


class Server:
    def __init__(self):
        self.socket = None
        self.clients_sockets = []
        self.db = Database('server_db.db')
        self.key_ids = []
        self.client_list_lock = threading.Lock()
        self.threads = []

    def handle_client(self, client_socket, client_addr):
        with self.client_list_lock:
            self.clients_sockets.append(client_socket)

        client_protocol = Protocol()
        client_id = self.exchange_keys_with_client(client_socket, client_protocol)

        identified = False

        while not identified:
            message_dict = client_protocol.receive_message(client_socket)

            if message_dict['type'] == 'Login':
                data = client_protocol.decrypt_message(message_dict)
                username, password = data.split()
                identified = self.check_login(username, password)
            elif message_dict['type'] == 'Signup':
                data = client_protocol.decrypt_message(message_dict)
                username, password = data.split()
                identified = self.signup_new_client(username, password)

            if not identified:
                client_protocol.send_message(client_socket, 'Server', client_id, 'Status', 'Invalid')

        client_protocol.send_message(client_socket, 'Server', client_id, 'Status', 'Confirmed')

        print('here')

    def run(self):
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.bind(('localhost', 8080))
        self.socket = server_socket

        self.socket.listen()

        try:
            while True:
                client_socket, addr = self.socket.accept()
                thread = threading.Thread(target=self.handle_client, args=(client_socket, addr), daemon=True)
                thread.start()
                self.threads.append(thread)
        except KeyboardInterrupt:
            print("\n[!] Server shutting down.")
        finally:
            with self.client_list_lock:
                for client in self.clients_sockets:
                    client.close()
            self.socket.close()

    def exchange_keys_with_client(self, client_socket, protocol: Protocol):
        # Receive Client's public RSA key
        public_key_message = protocol.receive_public_rsa_key(client_socket)
        public_key = public_key_message['data']
        sender = public_key_message['sender']

        # Generate AES key for communication with client
        protocol.aes.generate_key("my_secure_password")

        # Send generated AES key
        protocol.send_aes_key(client_socket, 'Server', sender, public_key)

        self.db.insert_instance(sender, protocol)
        return sender

    def check_login(self, username, password):
        return True

    def signup_new_client(self, username, password):
        return True


if __name__ == '__main__':
    # protocol = Protocol()
    # protocol.rsa.generate_keys()
    #
    # server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # server_socket.bind(('localhost', 8080))
    # server_socket.listen(5)
    #
    # while True:
    #     client_socket, client_address = server_socket.accept()
    #
    #     protocol.send_public_rsa_key(client_socket, 'Server', 'Client')
    #     print(protocol.rsa.public_key)
    #
    #     sender, target, encrypted_key = protocol.receive_aes_message(client_socket)
    #     aes_key = protocol.decrypt_aes_key(encrypted_key)
    #     print(sender, target, aes_key)
    #
    #     protocol.aes.set_key(aes_key)
    #
    #     message_dict = protocol.receive_message(client_socket)
    #     text = protocol.decrypt_message(message_dict)
    #     print(text)
    #     client_socket.close()

    server = Server()
    server.run()
