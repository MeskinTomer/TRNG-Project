"""
Author: Tomer Meskin
Date: 17/04/2025

Description: Client
"""

import socket
from RSA import RSA
from AES import AES
from Generator import Generator
from Protocol import Protocol
from DataBase import Database
from GUI import ChatApp
from PriorityLock import PriorityLock
import logging
import os
import threading
import queue

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


class Client:
    def __init__(self):
        self.socket = None
        self.db = Database()
        self.key_ids = []
        self.gui = ChatApp()
        self.server_protocol = Protocol()
        self.send_queue = queue.Queue()  # GUI puts messages here
        self.id = None
        self.lock = PriorityLock()

        self.gui.frames[self.gui.ChatScreen].set_send_callback(self.enqueue_message)
        self.gui.frames[self.gui.LoginScreen].set_send_callback(self.enqueue_message)
        self.gui.frames[self.gui.SignupScreen].set_send_callback(self.enqueue_message)

    def enqueue_message(self, data):
        self.send_queue.put(data)

    def run(self):
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect(('localhost', 8080))
        self.socket = client_socket

        self.exchange_keys_server()

    def exchange_keys_server(self):
        # Receive Server's public RSA key
        public_key_message = self.server_protocol.receive_public_rsa_key(self.socket)
        print(public_key_message)

        # Generate AES key for communication with server
        self.server_protocol.aes.generate_key("my_secure_password")

        # Send generated AES key
        self.server_protocol.send_aes_key(self.socket, 'Client', 'Server', public_key_message['data'])
        print(self.server_protocol.aes.key)

    def broadcast_public_key(self):
        self.enqueue_message(('Command', 'broadcast_public_key', None))

    def sender_thread(self):
        while True:
            try:
                message = self.send_queue.get()
                print(message)

                match message[0]:
                    case 'command':
                        pass
                    case 'Login':
                        pass
                    case 'Signup':
                        pass
                    case 'Message':
                        pass

            except queue.Empty:
                break

            except Exception as e:
                logger.error(f"[SenderThread] {e}")

    def receiver_thread(self):
        while True:
            try:
                message_dict = self.server_protocol.receive_message(self.socket)
                if message_dict is None:
                    break

                if message_dict['type'] == 'message':
                    pass
                else:
                    pass
            except Exception as e:
                logger.error(f"[ReceiverThread] {e}")
                break

    def new_client_join(self):
        self.lock.acquire('A')

        # Broadcast RSA public key
        self.server_protocol.send_public_rsa_key(self.socket, self.id, 'Broadcast')

        # Receive clients amount and receive AES keys
        amount_dict = self.server_protocol.receive_clients_amount(self.socket)
        amount = amount_dict['data']

        for i in range(amount):
            temp_protocol = Protocol()
            sender, target, encrypted_key = self.server_protocol.receive_aes_message(self.socket)
            aes_key = self.server_protocol.decrypt_aes_key(encrypted_key)

            temp_protocol.aes.set_key(aes_key)
            self.db.insert_instance(sender, temp_protocol)
            self.key_ids.append(sender)

        self.lock.release()

    def new_client_response(self):
        self.lock.acquire('A')

        # Receive public RSA key
        public_key_dict = self.server_protocol.receive_public_rsa_key(self.socket)
        public_key = public_key_dict['data']
        sender = public_key_dict['sender']

        # Generate Protocol instance and AES key
        temp_protocol = Protocol()
        temp_protocol.aes.generate_key("my_secure_password")
        self.db.insert_instance(sender, temp_protocol)
        self.key_ids.append(sender)

        # Send AES key
        self.server_protocol.send_aes_key(self.socket, self.id, sender, public_key)

    def test(self):
        t = threading.Thread(target=self.sender_thread, args=())
        t.start()
        self.gui.mainloop()
        t.join()


if __name__ == '__main__':
    # protocol = Protocol()
    # protocol.aes.generate_key("my_secure_password")
    #
    # client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # client_socket.connect(('localhost', 8080))
    #
    # public_key_message = protocol.receive_public_rsa_key(client_socket)
    # print(public_key_message)
    #
    # protocol.send_aes_key(client_socket, 'Client', 'Server', public_key_message['data'])
    # print(protocol.aes.key)
    #
    # protocol.send_message(client_socket, 'Client', 'Server', 'Hello World!')

    client = Client()
    client.test()
