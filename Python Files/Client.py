"""
Author: Tomer Meskin
Date: 17/04/2025

Description: Client
"""

import socket
from Protocol import Protocol
from GUI import ChatApp, ChatScreen, LoginScreen, SignupScreen
from PriorityLock import PriorityLock
import hashlib
import logging
import os
import threading
import queue

FILE_PATH_LOGS_FOLDER = os.path.join(os.path.dirname(__file__), '..', 'Log Files')
global logger


def setup_logger():
    """Sets up a logger specific to a client (e.g., Alice, Bob) that logs to file only with timestamps."""
    logger_name = f'Client'
    log_file = os.path.join(FILE_PATH_LOGS_FOLDER, f'Client.log')

    temp_logger = logging.getLogger(logger_name)
    temp_logger.setLevel(logging.DEBUG)

    # Prevent duplicate handlers
    if temp_logger.hasHandlers():
        temp_logger.handlers.clear()

    # File Handler only — no StreamHandler
    file_handler = logging.FileHandler(log_file, mode='w')
    file_formatter = logging.Formatter('%(asctime)s - %(levelname)s: %(message)s')
    file_handler.setFormatter(file_formatter)
    temp_logger.addHandler(file_handler)

    return temp_logger


class Client:
    def __init__(self):
        self.id = None
        global logger
        logger = setup_logger()

        self.socket = None
        self.protocols = {}
        self.key_ids = []
        self.gui = ChatApp()
        self.server_protocol = Protocol(logger)
        self.send_queue = queue.Queue()
        self.lock = PriorityLock()
        self.threads = []
        self.clients_usernames = {}

        logger.info("Initializing GUI and setting callbacks")
        self.gui.frames[self.gui.ChatScreen].set_send_callback(self.enqueue_message)
        self.gui.frames[self.gui.LoginScreen].set_send_callback(self.enqueue_message)
        self.gui.frames[self.gui.SignupScreen].set_send_callback(self.enqueue_message)

    def enqueue_message(self, data):
        logger.debug(f"Enqueuing message: {data}")
        self.send_queue.put(data)

    def run(self):
        logger.info("Starting client and connecting to server...")
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect(('localhost', 8080))
        self.socket = client_socket
        logger.info("Connected to server")

        self.exchange_keys_server()
        logger.info("RSA public key exchanged and AES key received from server")

        message_dict = self.server_protocol.receive_message(self.socket)
        self.id = self.server_protocol.decrypt_message(message_dict)
        logger.info(f"Received client ID: {self.id}")

        t = threading.Thread(target=self.start_communication, args=())
        t.start()
        self.threads.append(t)

        self.gui.mainloop()

        for thread in self.threads:
            thread.join()

    def start_communication(self):
        logger.info("Starting communication thread")
        identified = False
        while not identified:
            message = self.send_queue.get()
            logger.debug(f"Processing authentication message: {message[0]}")

            match message[0]:
                case 'Login':
                    username, password = message[1]
                    password_hash = hashlib.sha256(password.encode()).hexdigest()
                    identification = f"{username} {password_hash}"
                    logger.info(f"Attempting login for user: {username}")
                    self.server_protocol.send_message(self.socket, self.id, 'Server', 'Login', identification)

                    message_dict = self.server_protocol.receive_message(self.socket)
                    if message_dict['type'] == 'Status':
                        status = self.server_protocol.decrypt_message(message_dict)
                        identified = status == 'Confirmed'
                        logger.info(f"Login status for {username}: {status}")
                        self.gui.after(0, lambda: self.gui.
                                       frames[LoginScreen].receive_login_result(identified, self.gui))

                case 'Signup':
                    username, password = message[1]
                    password_hash = hashlib.sha256(password.encode()).hexdigest()
                    identification = f"{username} {password_hash}"
                    logger.info(f"Attempting signup for user: {username}")
                    self.server_protocol.send_message(self.socket, self.id, 'Server', 'Signup', identification)

                    message_dict = self.server_protocol.receive_message(self.socket)
                    if message_dict['type'] == 'Status':
                        status = self.server_protocol.decrypt_message(message_dict)
                        identified = status == 'Confirmed'
                        logger.info(f"Signup status for {username}: {status}")
                        self.gui.after(0, lambda: self.gui.
                                       frames[SignupScreen].receive_signup_result(identified, self.gui))

        self.new_client_join()
        t_sender = threading.Thread(target=self.sender_thread)
        t_receiver = threading.Thread(target=self.receiver_thread)

        t_sender.start()
        t_receiver.start()
        self.threads.extend([t_sender, t_receiver])

    def exchange_keys_server(self):
        logger.info("Generating RSA key pair and sending to server")
        self.server_protocol.rsa.generate_keys()
        self.server_protocol.send_public_rsa_key(self.socket, 'no id', 'Server')

        sender, target, encrypted_key = self.server_protocol.receive_aes_message(self.socket)
        aes_key = self.server_protocol.decrypt_aes_key(encrypted_key)
        self.server_protocol.aes.set_key(aes_key)
        logger.info("Received and set AES key for server communication")

    def broadcast_public_key(self):
        logger.info("Enqueuing broadcast public key command")
        self.enqueue_message(('Command', 'broadcast_public_key', None))

    def sender_thread(self):
        logger.info("Sender thread started")
        while True:
            self.lock.acquire('B')
            try:
                message = self.send_queue.get(timeout=1)
                logger.debug(f"Sender thread got message: {message}")

                if message[0] == 'Message':
                    self.broadcast_message(message)
                elif message[0] == 'Disconnect':
                    self.disconnect()
            except queue.Empty:
                continue
            except Exception as e:
                logger.error(f"[SenderThread] {e}")
            finally:
                self.lock.release()

    def receiver_thread(self):
        logger.info("Receiver thread started")
        while True:
            try:
                message_dict = self.server_protocol.receive_message(self.socket)
                if message_dict is None:
                    logger.info("Server disconnected")
                    break

                logger.debug(f"Received message dict: {message_dict}")
                if message_dict['type'] == 'message':
                    self.display_received_message(message_dict)
                elif message_dict['type'] == 'command':
                    data = self.server_protocol.decrypt_message(message_dict)
                    logger.info(f"Received command: {data}")
                    if data == 'new client':
                        self.new_client_response()
                    elif data == 'disconnect client':
                        self.disconnect_response()
            except Exception as e:
                logger.error(f"[ReceiverThread] {e}")
                break

    def new_client_join(self):
        logger.info("Handling new client join protocol")
        self.lock.acquire('A')

        self.server_protocol.send_public_rsa_key(self.socket, self.id, 'Broadcast')
        amount_dict = self.server_protocol.receive_clients_amount(self.socket)
        amount = int(amount_dict['data'])
        logger.info(f"{amount} clients in the system; receiving their AES keys and usernames")

        for i in range(amount):
            temp_protocol = Protocol(logger)
            sender, target, encrypted_key = self.server_protocol.receive_aes_message(self.socket)
            aes_key = self.server_protocol.decrypt_aes_key(encrypted_key)
            temp_protocol.aes.set_key(aes_key)

            self.protocols[sender] = temp_protocol
            self.key_ids.append(sender)

            message_dict = self.server_protocol.receive_message(self.socket)
            username = self.server_protocol.decrypt_message(message_dict)
            self.clients_usernames[sender] = username
            logger.info(f"Connected to client '{username}' with ID: {sender}")
            self.gui.after(0, lambda: self.gui.frames[ChatScreen].add_active_user(username))

        self.lock.release()

    def new_client_response(self):
        logger.info("Responding to new client broadcast")
        self.lock.acquire('A')

        public_key_dict = self.server_protocol.receive_public_rsa_key(self.socket)
        public_key = public_key_dict['data']
        sender = public_key_dict['sender']
        logger.info(f"Received new client's public RSA key from {sender}")

        temp_protocol = Protocol(logger)
        temp_protocol.aes.generate_key("my_secure_password")
        self.protocols[sender] = temp_protocol
        self.key_ids.append(sender)

        self.server_protocol.send_message(self.socket, self.id, 'Server', 'alert', 'AES key incoming')
        temp_protocol.send_aes_key(self.socket, self.id, sender, public_key)

        message_dict = self.server_protocol.receive_message(self.socket)
        username = self.server_protocol.decrypt_message(message_dict)
        self.clients_usernames[sender] = username
        logger.info(f"New client '{username}' connected with ID: {sender}")
        self.gui.after(0, lambda: self.gui.frames[ChatScreen].add_active_user(username))

        self.lock.release()

    def broadcast_message(self, message):
        logger.info(f"Broadcasting message to {len(self.key_ids)} clients")
        for target_id in self.key_ids:
            logger.debug(f"Sending message to client ID: {target_id}")
            target_protocol = self.protocols[target_id]
            target_protocol.send_message(self.socket, self.id, target_id, 'message', message[1])

    def display_received_message(self, message_dict):
        temp_protocol = self.protocols[message_dict['sender']]
        text = temp_protocol.decrypt_message(message_dict)
        username = self.clients_usernames[message_dict['sender']]
        logger.info(f"Received message from {username}")
        self.gui.after(0, lambda: self.gui.frames[ChatScreen].receive_message(username, text))

    def disconnect(self):
        logger.info("Sending disconnect command to server")
        self.server_protocol.send_message(self.socket, self.id, 'Server', 'command', 'Disconnected')

    def disconnect_response(self):
        message_dict = self.server_protocol.receive_message(self.socket)
        disconnect_id = self.server_protocol.decrypt_message(message_dict)

        username = self.clients_usernames[disconnect_id]
        logger.info(f"Client '{username}' disconnected")
        self.gui.after(0, lambda: self.gui.frames[ChatScreen].remove_active_user(username))

        del self.protocols[disconnect_id]
        self.key_ids.remove(disconnect_id)
        self.clients_usernames.pop(disconnect_id)

    def test(self):
        t = threading.Thread(target=self.sender_thread, args=())
        t.start()
        self.gui.mainloop()
        t.join()


if __name__ == '__main__':
    client = Client()
    client.run()
