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
from GUI import ChatScreen
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
        self.db = Database('client_db2.db')
        self.key_ids = []
        self.gui = ChatApp()
        self.server_protocol = Protocol()
        self.send_queue = queue.Queue()  # GUI puts messages here
        self.id = 'alon'
        self.lock = PriorityLock()
        self.threads = []

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

        t = threading.Thread(target=self.start_communication, args=())
        t.start()
        self.threads.append(t)

        self.gui.mainloop()

        for thread in self.threads:
            thread.join()

    def start_communication(self):
        identified = False
        while not identified:
            message = self.send_queue.get()

            match message[0]:
                case 'Login':
                    username, password = message[1]
                    identification = username + ' ' + password
                    self.server_protocol.send_message(self.socket, self.id, 'Server', 'Login', identification)

                    message_dict = self.server_protocol.receive_message(self.socket)
                    status = self.server_protocol.decrypt_message(message_dict)
                    if message_dict['type'] == 'Status' and status == 'Confirmed':
                        identified = True
                case 'Signup':
                    username, password = message[1]
                    identification = username + ' ' + password
                    self.server_protocol.send_message(self.socket, self.id, 'Server', 'Signup', identification)

                    message_dict = self.server_protocol.receive_message(self.socket)
                    status = self.server_protocol.decrypt_message(message_dict)
                    if message_dict['type'] == 'Status' and status == 'Confirmed':
                        identified = True

        self.new_client_join()

        t_sender = threading.Thread(target=self.sender_thread, args=())
        t_receiver = threading.Thread(target=self.receiver_thread, args=())

        t_sender.start()
        t_receiver.start()
        self.threads.append(t_sender)
        self.threads.append(t_receiver)

    def exchange_keys_server(self):
        # Send Client's public RSA key
        self.server_protocol.rsa.generate_keys()
        self.server_protocol.send_public_rsa_key(self.socket, self.id, 'Server')

        # Receive and set AES key for communication with server
        sender, target, encrypted_key = self.server_protocol.receive_aes_message(self.socket)
        aes_key = self.server_protocol.decrypt_aes_key(encrypted_key)

        self.server_protocol.aes.set_key(aes_key)

    def broadcast_public_key(self):
        self.enqueue_message(('Command', 'broadcast_public_key', None))

    def sender_thread(self):
        while True:
            self.lock.acquire('B')
            try:
                message = self.send_queue.get(timeout=1)

                if message[0] == 'command':
                    pass
                elif message[0] == 'Message':
                    self.broadcast_message(message)
            except queue.Empty:
                continue

            except Exception as e:
                logger.error(f"[SenderThread] {e}")
            finally:
                self.lock.release()

    def receiver_thread(self):
        while True:
            try:
                message_dict = self.server_protocol.receive_message(self.socket)
                if message_dict is None:
                    break

                if message_dict['type'] == 'message':
                    self.display_received_message(message_dict)
                elif message_dict['type'] == 'command':
                    print('he re')
                    self.new_client_response()
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
        amount = int(amount_dict['data'])

        for i in range(amount):
            temp_protocol = Protocol()
            sender, target, encrypted_key = self.server_protocol.receive_aes_message(self.socket)
            aes_key = self.server_protocol.decrypt_aes_key(encrypted_key)

            temp_protocol.aes.set_key(aes_key)
            self.db.insert_instance(sender, temp_protocol)
            self.key_ids.append(sender)
            self.gui.after(0, lambda: self.gui.frames[ChatScreen].add_active_user(sender))

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

        self.gui.after(0, lambda: self.gui.frames[ChatScreen].add_active_user(sender))
        self.lock.release()

    def broadcast_message(self, message):
        for target_id in self.key_ids:
            print('broadcast')
            target_protocol = self.db.get_instance_by_client_id(target_id)
            target_protocol.send_message(self.socket, self.id, target_id, 'message', message[1])

    def display_received_message(self, message_dict):
        temp_protocol = self.db.get_instance_by_client_id(message_dict['sender'])
        text = temp_protocol.decrypt_message(message_dict)

        self.gui.after(0, lambda: self.gui.frames[ChatScreen].receive_message(message_dict['sender'], text))

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
    client.run()
