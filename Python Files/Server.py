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
import queue

FILE_PATH_LOGS_FOLDER = os.path.join(os.path.dirname(__file__), '..', 'Log Files')


def setup_client_logger():
    """Sets up a logger specific to a client (e.g., Alice, Bob)."""
    logger_name = 'Server'
    log_file = os.path.join(FILE_PATH_LOGS_FOLDER, 'Server.log')

    logger = logging.getLogger(logger_name)
    logger.setLevel(logging.DEBUG)

    # Prevent duplicate handlers if already set
    if logger.hasHandlers():
        logger.handlers.clear()

    handler = logging.FileHandler(log_file, mode='w')
    formatter = logging.Formatter('%(levelname)s: %(message)s')
    handler.setFormatter(formatter)
    logger.addHandler(handler)

    return logger


logger = None


class Server:
    def __init__(self):
        self.socket = None
        self.clients_sockets = {}
        self.db = Database('server_db.db')
        self.client_list_lock = threading.Lock()
        self.threads = []
        self.transfer_queue = queue.Queue()

        global logger
        logger = setup_client_logger()

    def handle_client(self, client_socket, client_addr):
        client_protocol = Protocol(logger)
        client_id = self.exchange_keys_with_client(client_socket, client_protocol)

        with self.client_list_lock:
            self.clients_sockets[client_id] = client_socket

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
                identified = self.check_signup(username, password)

            if not identified:
                client_protocol.send_message(client_socket, 'Server', client_id, 'Status', 'Invalid')

        client_protocol.send_message(client_socket, 'Server', client_id, 'Status', 'Confirmed')
        self.new_client_operation(client_socket, client_protocol ,client_id)

        disconnected = False
        while not disconnected:
            message_dict = client_protocol.receive_message(client_socket)
            if message_dict['target'] == 'Server':
                if message_dict['type'] == 'alert':
                    data = client_protocol.decrypt_message(message_dict)
                    if data == 'AES key incoming':
                        sender, target, encrypted_key = client_protocol.receive_aes_message(client_socket)
                        self.transfer_queue.put((sender, target, encrypted_key))
            elif message_dict['target'] != 'Server':
                self.message_transfer_operation(client_socket, client_protocol, client_id, message_dict)

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

    def check_signup(self, username, password):
        return True

    def new_client_operation(self, client_socket, client_protocol: Protocol, client_id):
        rsa_message_dict = client_protocol.receive_public_rsa_key(client_socket)

        clients_amount = len(self.clients_sockets) - 1
        client_protocol.send_clients_amount(client_socket, 'Server', client_id, clients_amount)

        for temp_id, temp_socket in self.clients_sockets.items():
            if temp_id != client_id:
                temp_protocol = self.db.get_instance_by_client_id(temp_id)
                temp_protocol.rsa.set_public_key(rsa_message_dict['data'])

                temp_protocol.send_message(temp_socket, 'Server', temp_id, 'command', 'new client')
                temp_protocol.send_public_rsa_key(temp_socket, client_id, temp_id)
                print('here 2')
                sender, target, encrypted_key = self.transfer_queue.get()
                print('here 3')
                client_protocol.send_aes_key(client_socket, temp_id, client_id, None, True, encrypted_key)

    def message_transfer_operation(self, client_socket, client_protocol, client_id, message_dict):
        temp_protocol = self.db.get_instance_by_client_id(message_dict['target'])
        temp_socket = self.clients_sockets[message_dict['target']]

        temp_protocol.send_message(temp_socket, client_id, message_dict['target'], 'message', message_dict['data'], True)


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
