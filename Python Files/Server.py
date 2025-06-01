"""
Author: Tomer Meskin
Date: 17/04/2025

Description: Server
"""

import socket
import threading
from ClientsDB import ClientDatabase
from Protocol import Protocol
import logging
import os
import queue

FILE_PATH_LOGS_FOLDER = os.path.join(os.path.dirname(__file__), '..', 'Log Files')


def setup_logger():
    """Sets up a logger specific to a client (e.g., Alice, Bob)."""
    logger_name = 'Server'
    log_file = os.path.join(FILE_PATH_LOGS_FOLDER, 'Server.log')

    temp_logger = logging.getLogger(logger_name)
    temp_logger.setLevel(logging.DEBUG)

    # Prevent duplicate handlers if already set
    if temp_logger.hasHandlers():
        temp_logger.handlers.clear()

    handler = logging.FileHandler(log_file, mode='w')
    formatter = logging.Formatter('%(asctime)s | %(levelname)s | %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
    handler.setFormatter(formatter)
    temp_logger.addHandler(handler)

    return temp_logger


logger = None


class Server:
    def __init__(self):
        self.socket = None
        self.clients_sockets = {}
        self.clients_usernames = {}
        self.db = {}
        self.usernames_passwords_db = None
        self.client_list_lock = threading.Lock()
        self.threads = []
        self.transfer_queue = queue.Queue()
        self.last_id = 0

        global logger
        logger = setup_logger()

    def handle_client(self, client_socket):
        client_protocol = Protocol(logger)
        self.exchange_keys_with_client(client_socket, client_protocol)

        self.last_id += 1
        client_id = str(self.last_id)
        client_protocol.send_message(client_socket, 'Server', client_id, 'identification', client_id)
        self.db[client_id] = client_protocol

        with self.client_list_lock:
            self.clients_sockets[client_id] = client_socket

        self.usernames_passwords_db = ClientDatabase()
        username, password = None, None
        identified = False
        while not identified:
            message_dict = client_protocol.receive_message(client_socket)

            if message_dict['type'] == 'login':
                data = client_protocol.decrypt_message(message_dict)
                username, password = data.split()
                identified = self.usernames_passwords_db.verify(username, password)
            elif message_dict['type'] == 'signup':
                data = client_protocol.decrypt_message(message_dict)
                username, password = data.split()
                identified = self.usernames_passwords_db.insert(username, password)

            if not identified:
                client_protocol.send_message(client_socket, 'Server', client_id, 'status', 'Invalid')

        self.usernames_passwords_db.close()
        client_protocol.send_message(client_socket, 'Server', client_id, 'status', 'Confirmed')
        self.clients_usernames[client_id] = username
        self.new_client_operation(client_socket, client_protocol, client_id, username)

        disconnected = False
        while not disconnected:
            message_dict = client_protocol.receive_message(client_socket)
            if message_dict['target'] == 'Server':
                data = client_protocol.decrypt_message(message_dict)
                if message_dict['type'] == 'alert':
                    if data == 'AES key incoming':
                        aes_dict = client_protocol.receive_aes_message(client_socket)
                        self.transfer_queue.put(aes_dict)
                elif message_dict['type'] == 'command':
                    if data == 'Disconnected':
                        self.disconnect_client(client_id)
            elif message_dict['target'] != 'Server':
                self.message_transfer_operation(client_id, message_dict)

    def run(self):
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.bind(('localhost', 8080))
        self.socket = server_socket

        self.socket.listen()

        try:
            while True:
                client_socket, addr = self.socket.accept()
                thread = threading.Thread(target=self.handle_client, args=(client_socket,), daemon=True)
                thread.start()
                self.threads.append(thread)
        except KeyboardInterrupt:
            print("\n[!] Server shutting down.")
        finally:
            with self.client_list_lock:
                for client in self.clients_sockets:
                    client.close()
            self.socket.close()

    @staticmethod
    def exchange_keys_with_client(client_socket, protocol: Protocol):
        public_key_message = protocol.receive_public_rsa_key(client_socket)
        public_key = public_key_message['data']
        sender = public_key_message['sender']

        protocol.aes.generate_key("my_secure_password")
        protocol.send_aes_key(client_socket, 'Server', sender, public_key)

    def new_client_operation(self, client_socket, client_protocol: Protocol, client_id, username):
        rsa_message_dict = client_protocol.receive_public_rsa_key(client_socket)

        clients_amount = len(self.clients_usernames) - 1
        client_protocol.send_message(client_socket, 'Server', client_id, 'clients amount', str(clients_amount))

        for temp_id, temp_socket in self.clients_sockets.items():
            if temp_id != client_id and temp_id in self.clients_usernames.keys():
                temp_protocol = self.db[temp_id]
                temp_protocol.rsa.set_public_key(rsa_message_dict['data'])

                temp_protocol.send_message(temp_socket, 'Server', temp_id, 'command', 'new client')
                temp_protocol.send_public_rsa_key(temp_socket, client_id, temp_id)

                aes_dict = self.transfer_queue.get()
                encrypted_key = aes_dict['data']

                client_protocol.send_aes_key(client_socket, temp_id, client_id,
                                             None, True, encrypted_key)

                temp_protocol.send_message(temp_socket, 'Server', temp_id, 'username', username)
                client_protocol.send_message(client_socket, 'Server', client_id,
                                             'username', self.clients_usernames[temp_id])

    def message_transfer_operation(self, client_id, message_dict):
        temp_protocol = self.db[message_dict['target']]
        temp_socket = self.clients_sockets[message_dict['target']]

        temp_protocol.send_message(temp_socket, client_id,
                                   message_dict['target'], 'message', message_dict['data'], True)

    def disconnect_client(self, client_id):
        for temp_id, temp_socket in self.clients_sockets.items():
            if temp_id != client_id and temp_id in self.clients_usernames.keys():
                temp_protocol = self.db[temp_id]

                temp_protocol.send_message(temp_socket, 'Server', temp_id, 'command', 'disconnect client')
                temp_protocol.send_message(temp_socket, 'Server', temp_id, 'disconnect id', client_id)

        self.db.pop(client_id)
        self.clients_usernames.pop(client_id)
        self.clients_sockets.pop(client_id)


if __name__ == '__main__':
    server = Server()
    server.run()
