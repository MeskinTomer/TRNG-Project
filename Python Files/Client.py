"""
Author: Tomer Meskin
Date: 17/04/2025

Description: This module implements the client-side logic for a chat application.
It handles connection to a server, user authentication (login/signup),
secure key exchange, encrypted message communication with other clients,
and integration with a GUI for user interaction.
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
import re

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
        self.id = None  # Unique ID assigned by the server after connection
        global logger
        logger = setup_logger()  # Set up the global logger for the client

        self.socket = None  # The client's socket connection to the server
        self.protocols = {}  # Dictionary to store Protocol instances for each connected client
        self.clients_ids = []  # List of IDs of other connected clients
        self.gui = ChatApp()  # Instance of the GUI application
        self.server_protocol = Protocol(logger)  # Protocol instance for communication with the server
        self.send_queue = queue.Queue()  # Queue for messages to be sent by the sender thread
        self.lock = PriorityLock()  # Custom lock for managing concurrent access with priorities
        self.threads = []  # List to keep track of active threads
        self.clients_usernames = {}  # Dictionary to map client IDs to their usernames
        self.disconnected = False  # Flag to indicate if the client has initiated disconnection

        try:
            # Set callback functions for GUI screens to enqueue user actions (e.g., sending messages, login attempts)
            self.gui.frames[self.gui.ChatScreen].set_send_callback(self.enqueue_message)
            self.gui.frames[self.gui.LoginScreen].set_send_callback(self.enqueue_message)
            self.gui.frames[self.gui.SignupScreen].set_send_callback(self.enqueue_message)
        except AttributeError as e:
            logger.error(f"Failed to set GUI callbacks: {e}. Ensure GUI frames are correctly initialized.")
        except Exception as e:
            logger.critical(f"An unexpected error occurred during GUI initialization: {e}")

    def run(self):
        """
        Starts the client application.
        Establishes a connection to the server, exchanges encryption keys,
        receives its unique ID, and then initiates the communication threads
        (sender and receiver). Finally, it starts the GUI main loop.
        """
        logger.info("Starting client and connecting to server...")
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            client_socket.connect(('localhost', 8080))
            self.socket = client_socket
            logger.info("Successfully connected to server at ('localhost', 8080).")
            # Assert that the socket is indeed connected
            assert self.socket is not None, "Client socket was not established."

        except socket.error as e:
            logger.critical(f"Failed to connect to server: {e}. Please ensure the server is running.")
            self.gui.destroy()  # Close the GUI if connection fails
            return
        except Exception as e:
            logger.critical(f"An unexpected error occurred during socket connection: {e}")
            self.gui.destroy()
            return

        try:
            self.exchange_keys_server()
            logger.info("RSA public key exchanged with server, and AES key received for server communication.")

            message_dict = self.server_protocol.receive_message(self.socket)
            if message_dict is None:
                logger.error("Did not receive client ID from server. Connection issue?")
                self.socket.close()
                self.gui.destroy()
                return

            self.id = self.server_protocol.decrypt_message(message_dict)
            logger.info(f"Received client ID: {self.id}")
            # Assert that a client ID has been assigned
            assert self.id is not None, "Client ID was not received from the server."

            # Start the main communication thread which handles authentication and subsequent messaging
            t = threading.Thread(target=self.start_communication, args=(), name="CommunicationThread")
            t.daemon = True  # Allow the main program to exit even if this thread is still running
            t.start()
            self.threads.append(t)
        except Exception as e:
            logger.critical(f"Error during initial key exchange or ID reception: {e}")
            self.socket.close()
            self.gui.destroy()
            return

        logger.info("Starting GUI main loop.")
        self.gui.mainloop()

        logger.info("GUI main loop exited. Waiting for communication threads to finish...")
        # Join all threads to ensure they complete cleanly before the main program exits
        for thread in self.threads:
            # print(f"Joining thread: {thread.name}") # For debugging thread shutdown
            if thread.is_alive():
                thread.join(timeout=1)  # Give threads a chance to clean up
                if thread.is_alive():
                    logger.warning(f"Thread {thread.name} did not terminate gracefully.")
            # print(f"Joined thread: {thread.name}")

        logger.info("Closing client socket.")
        try:
            self.socket.close()
        except socket.error as e:
            logger.error(f"Error closing socket: {e}")
        logger.info("Client shutdown complete.")

    def start_communication(self):
        """
        Manages the initial authentication process (login/signup) with the server,
        then transitions into continuous sending and receiving of messages
        once authenticated.
        """
        logger.info("Starting communication thread for authentication and messaging.")
        identified = False
        while not identified and not self.disconnected:
            try:
                # Retrieve authentication messages from the send queue (from GUI)
                message = self.send_queue.get()
                logger.debug(f"Processing authentication message from GUI: {message[0]}")

                msg_type = message[0]
                username, password = message[1]

                # Check basic rules for username and password before sending to server
                is_valid, reason = self.basic_credentials_check(username, password)
                if not is_valid:
                    if msg_type == 'Login':
                        self.gui.after(0, lambda: self.gui.frames[LoginScreen].
                                       receive_login_result(False, self.gui))
                        continue
                    if msg_type == 'Signup':
                        self.gui.after(0, lambda: self.gui.frames[SignupScreen].
                                       receive_signup_result(False, self.gui))
                        continue

                password_hash = hashlib.sha256(password.encode()).hexdigest()
                identification_payload = f"{username} {password_hash}"

                if msg_type == 'Login':
                    logger.info(f"Attempting login for user: {username}")
                    self.server_protocol.send_message(self.socket, self.id, 'Server', 'login', identification_payload)

                elif msg_type == 'Signup':
                    logger.info(f"Attempting signup for user: {username}")
                    self.server_protocol.send_message(self.socket, self.id, 'Server', 'signup', identification_payload)
                else:
                    logger.warning(f"Unknown message type received during authentication: {msg_type}")
                    continue

                # Receive response from server
                message_dict = self.server_protocol.receive_message(self.socket)
                if message_dict and message_dict['type'] == 'status':
                    status = self.server_protocol.decrypt_message(message_dict)
                    identified = (status == 'Confirmed')
                    logger.info(f"Authentication status for {username} ({msg_type}): {status}")

                    # Update GUI based on authentication result
                    if msg_type == 'Login':
                        self.gui.after(0,
                                       lambda: self.gui.frames[LoginScreen].receive_login_result(identified, self.gui))
                    elif msg_type == 'Signup':
                        self.gui.after(0, lambda: self.gui.frames[SignupScreen].receive_signup_result(identified,
                                                                                                      self.gui))
                else:
                    logger.error(f"Received unexpected message type during authentication: {message_dict}")
            except queue.Empty:
                logger.debug("Authentication queue was empty (should not happen in this loop).")
                continue  # Should not happen as get() is blocking by default
            except socket.error as e:
                logger.error(f"Socket error during authentication: {e}. Server might have disconnected.")
                self.disconnected = True  # Set disconnected flag to exit loop
                break
            except Exception as e:
                logger.critical(f"An unexpected error occurred during authentication: {e}")
                self.disconnected = True  # Exit on unexpected errors
                break

        if self.disconnected:
            logger.info("Exiting start_communication due to disconnection.")
            return

        logger.info("Client identified. Proceeding to main communication phase.")
        # Assert that the client is identified before proceeding
        assert identified, "Client failed to be identified after authentication loop."

        # After successful authentication, initiate the new client join process
        try:
            self.new_client_join()
        except Exception as e:
            logger.critical(f"Error during initial client join process after authentication: {e}")
            self.disconnected = True
            return

        # Start sender and receiver threads for ongoing communication
        t_sender = threading.Thread(target=self.sender_thread, name="SenderThread")
        t_receiver = threading.Thread(target=self.receiver_thread, name="ReceiverThread")

        t_sender.daemon = True
        t_receiver.daemon = True

        t_sender.start()
        t_receiver.start()
        self.threads.extend([t_sender, t_receiver])
        logger.info("Sender and Receiver threads started.")

    def exchange_keys_server(self):
        """
        Performs the initial key exchange with the server.
        Generates an RSA key pair, sends the public key to the server,
        and then receives and sets the AES key provided by the server
        for encrypted communication.
        """
        logger.info("Generating RSA key pair and sending public key to server.")
        try:
            self.server_protocol.rsa.generate_keys()
            self.server_protocol.send_public_rsa_key(self.socket, 'no id',
                                                     'Server')  # 'no id' as ID is not yet assigned

            aes_dict = self.server_protocol.receive_aes_message(self.socket)
            if not aes_dict or 'data' not in aes_dict:
                raise ValueError("Did not receive valid AES key dictionary from server.")

            aes_key = self.server_protocol.decrypt_aes_key(aes_dict['data'])
            self.server_protocol.aes.set_key(aes_key)
            logger.info("Received and set AES key for server communication successfully.")
            # Assert that the AES key is set on the server protocol
            assert self.server_protocol.aes.key is not None, "AES key was not set after exchange with server."
        except socket.error as e:
            logger.error(f"Socket error during key exchange with server: {e}")
            raise  # Re-raise to be caught by run() method
        except ValueError as e:
            logger.error(f"Data error during key exchange with server: {e}")
            raise
        except Exception as e:
            logger.critical(f"An unexpected error occurred during key exchange with server: {e}")
            raise

    def sender_thread(self):
        """
        Dedicated thread for sending messages from the send queue to the server.
        It continuously retrieves messages from `self.send_queue` and processes them.
        Handles message broadcasting and client disconnection requests.
        """
        logger.info("Sender thread started.")
        while not self.disconnected:
            self.lock.acquire('B')  # Acquire lock with 'B' priority
            try:
                # Attempt to get a message from the queue with a timeout
                # This allows the thread to check the `disconnected` flag periodically
                message = self.send_queue.get(timeout=0.5)
                logger.debug(f"Sender thread got message: {message[0]}")

                if message[0] == 'Message':
                    # If it's a chat message, broadcast it to other clients
                    self.broadcast_message(message)
                elif message[0] == 'Disconnect':
                    # If it's a disconnect command, initiate client disconnection
                    self.disconnect()
                else:
                    logger.warning(f"Sender thread received an unknown message type: {message[0]}")
            except queue.Empty:
                # No messages in the queue, continue loop to check `disconnected` flag
                continue
            except Exception as e:
                logger.error(f"[SenderThread] An error occurred while processing message: {e}")
                # Consider setting self.disconnected = True here if the error is critical
            finally:
                self.lock.release()
        logger.info("Sender thread exiting.")

    def receiver_thread(self):
        """
        Dedicated thread for receiving messages and commands from the server.
        It continuously listens for incoming data and dispatches it for processing,
        such as displaying chat messages or handling client join/disconnect commands.
        """
        logger.info("Receiver thread started.")
        while not self.disconnected:
            try:
                message_dict = self.server_protocol.receive_message(self.socket)
                if message_dict is None:
                    # Server disconnected gracefully or an error occurred leading to None
                    logger.info("Server disconnected or sent an empty message. Exiting receiver thread.")
                    self.disconnected = True
                    break

                logger.debug(f"Received message dict: {message_dict}")

                # Process message based on its type
                if message_dict.get('type') == 'message':
                    # Regular chat message from another client
                    self.display_received_message(message_dict)
                elif message_dict.get('type') == 'command':
                    # Server command (e.g., new client joined, client disconnected)
                    data = self.server_protocol.decrypt_message(message_dict)
                    logger.info(f"Received command: {data}")
                    # Assert that the decrypted command is not empty
                    assert data is not None and data != "", "Received empty or invalid command."

                    if data == 'new client':
                        self.new_client_response()
                    elif data == 'Disconnect':
                        # Server initiated disconnect
                        logger.info("Server commanded client to disconnect.")
                        self.disconnected = True
                        break
                    elif data == 'disconnect client':
                        self.disconnect_response()
                    else:
                        logger.warning(f"Unknown command received: {data}")
                else:
                    logger.warning(f"Received message with unknown or missing 'type': {message_dict}")

            except socket.error as e:
                logger.error(f"[ReceiverThread] Socket error: {e}. Server connection might be lost.")
                self.disconnected = True  # Set flag to terminate thread
                break
            except Exception as e:
                logger.error(f"[ReceiverThread] An unexpected error occurred: {e}")
                # It's safer to terminate the thread on unexpected errors to prevent infinite loops or crashes
                self.disconnected = True
                break
        logger.info("Receiver thread exiting.")

    def enqueue_message(self, data):
        """
        Enqueues a message or command to be sent by the sender thread.
        This method is typically called by the GUI when a user performs an action.

        Args:
            data (tuple): A tuple containing the message type and its content,
                          e.g., ('Message', 'Hello World'), ('Login', ('username', 'password')).
        """
        logger.debug(f"Enqueuing message: {data[0]}")
        try:
            self.send_queue.put(data)
        except Exception as e:
            logger.error(f"Error enqueuing message {data}: {e}")

    def new_client_join(self):
        """
        Handles the protocol for a client joining the existing chat network.
        This client sends its public RSA key to the server, then receives
        AES keys and usernames from all currently connected clients.
        It updates its internal `protocols`, `clients_ids`, and `clients_usernames` maps.
        This occurs when *this* client is the new client joining.
        """
        logger.info("Handling new client join protocol (this client is new).")
        self.lock.acquire('A')  # Acquire lock with 'A' priority for critical section
        try:
            # Send this client's public RSA key to the server so other clients can encrypt AES keys for it.
            self.server_protocol.send_public_rsa_key(self.socket, self.id, 'Broadcast')
            logger.info("Sent own public RSA key for broadcast to existing clients.")

            # Receive the amount of existing clients
            amount_dict = self.server_protocol.receive_message(self.socket)
            if not amount_dict:
                raise ValueError("Failed to receive amount of clients from server.")
            amount = int(self.server_protocol.decrypt_message(amount_dict))
            logger.info(f"Server reported {amount} existing clients; receiving their AES keys and usernames.")
            # Assert that amount is a non-negative integer
            assert isinstance(amount, int) and amount >= 0, "Received invalid client count."

            # Loop to receive AES keys and usernames from each existing client
            for i in range(amount):
                temp_protocol = Protocol(logger)  # Create a new protocol instance for each client

                aes_dict = self.server_protocol.receive_aes_message(self.socket)
                if not aes_dict or 'data' not in aes_dict or 'sender' not in aes_dict:
                    logger.warning(f"Skipping malformed AES key dict from server (iteration {i}): {aes_dict}")
                    continue

                aes_key = self.server_protocol.decrypt_aes_key(aes_dict['data'])
                sender_id = aes_dict['sender']
                temp_protocol.aes.set_key(aes_key)  # Set the received AES key for this client's protocol

                self.protocols[sender_id] = temp_protocol
                self.clients_ids.append(sender_id)

                message_dict = self.server_protocol.receive_message(self.socket)
                if not message_dict:
                    logger.warning(f"Failed to receive username for client ID {sender_id}. Skipping.")
                    continue

                username = self.server_protocol.decrypt_message(message_dict)
                self.clients_usernames[sender_id] = username
                logger.info(f"Connected to existing client '{username}' with ID: {sender_id}.")
                self.gui.after(0, lambda u=username: self.gui.frames[ChatScreen].add_active_user(u))

        except socket.error as e:
            logger.error(f"Socket error during new client join process: {e}")
        except ValueError as e:
            logger.error(f"Data processing error during new client join: {e}")
        except Exception as e:
            logger.critical(f"An unexpected error occurred during new client join: {e}")
        finally:
            self.lock.release()
        logger.info("New client join protocol finished.")

    def new_client_response(self):
        """
        Handles the protocol when a *new* client connects to the server.
        This client (an existing one) receives the new client's public RSA key,
        generates its own AES key, encrypts it with the new client's RSA public key,
        and sends it to the new client. It then receives the new client's username.
        """
        logger.info("Responding to a new client broadcast (this client is existing).")
        self.lock.acquire('A')  # Acquire lock with 'A' priority
        try:
            # Receive the new client's public RSA key
            public_key_dict = self.server_protocol.receive_public_rsa_key(self.socket)
            if not public_key_dict or 'data' not in public_key_dict or 'sender' not in public_key_dict:
                raise ValueError("Failed to receive valid public RSA key from new client.")

            public_key = public_key_dict['data']
            sender_id = public_key_dict['sender']
            logger.info(f"Received new client's public RSA key from ID: {sender_id}.")
            # Assert that the sender ID is new
            assert sender_id not in self.clients_ids, f"Received new client response for existing ID: {sender_id}"

            temp_protocol = Protocol(logger)
            # Generate a new AES key for communication with this new client
            temp_protocol.aes.generate_key('my secure password')
            self.protocols[sender_id] = temp_protocol
            self.clients_ids.append(sender_id)

            # Inform the server that an AES key is incoming for the new client
            self.server_protocol.send_message(self.socket, self.id, 'Server', 'alert', 'AES key incoming')
            # Send the newly generated AES key, encrypted with the new client's public RSA key
            temp_protocol.send_aes_key(self.socket, self.id, sender_id, public_key)
            logger.info(f"Sent AES key to new client ID: {sender_id}.")

            # Receive the new client's username
            message_dict = self.server_protocol.receive_message(self.socket)
            if not message_dict:
                raise ValueError(f"Failed to receive username for new client ID {sender_id}.")

            username = self.server_protocol.decrypt_message(message_dict)
            self.clients_usernames[sender_id] = username
            logger.info(f"New client '{username}' connected with ID: {sender_id}.")
            self.gui.after(0, lambda u=username: self.gui.frames[ChatScreen].add_active_user(u))

        except socket.error as e:
            logger.error(f"Socket error during new client response: {e}")
        except ValueError as e:
            logger.error(f"Data processing error during new client response: {e}")
        except Exception as e:
            logger.critical(f"An unexpected error occurred during new client response: {e}")
        finally:
            self.lock.release()
        logger.info("New client response protocol finished.")

    def broadcast_message(self, message):
        """
        Encrypts and sends a chat message to all other connected clients.

        Args:
            message (tuple): A tuple containing the message type ('Message') and the actual text content.
        """
        text_content = message[1]
        logger.info(f"Broadcasting message to {len(self.clients_ids)} clients.")
        if not self.clients_ids:
            logger.warning("No other clients to broadcast message to.")
            return

        for target_id in self.clients_ids:
            if target_id == self.id:  # Do not send message to self
                continue
            try:
                logger.debug(f"Sending message to client ID: {target_id}")
                target_protocol = self.protocols.get(target_id)
                if target_protocol:
                    target_protocol.send_message(self.socket, self.id, target_id, 'message', text_content)
                else:
                    logger.warning(f"No protocol found for target client ID: {target_id}. Skipping message.")
            except socket.error as e:
                logger.error(f"Socket error broadcasting message to {target_id}: {e}")
                # Consider removing the client from list if send fails repeatedly
            except Exception as e:
                logger.error(f"Error broadcasting message to {target_id}: {e}")

    def display_received_message(self, message_dict):
        """
        Decrypts a received message and displays it in the chat GUI.

        Args:
            message_dict (dict): The dictionary containing the encrypted message details.
        """
        sender_id = message_dict.get('sender')
        if not sender_id:
            logger.warning("Received message_dict without a sender ID.")
            return

        temp_protocol = self.protocols.get(sender_id)
        if not temp_protocol:
            logger.warning(f"No protocol found for sender ID {sender_id}. Cannot decrypt message.")
            return

        try:
            text = temp_protocol.decrypt_message(message_dict)
            username = self.clients_usernames.get(sender_id, f"Unknown User ({sender_id})")
            logger.info(f"Received message from {username}: '{text[:50]}...'")  # Log first 50 chars
            # Assert that the decrypted text is not empty
            assert text is not None and text != "", "Decrypted message was empty."

            self.gui.after(0, lambda u=username, t=text: self.gui.frames[ChatScreen].receive_message(u, t))
        except Exception as e:
            logger.error(f"Error decrypting or displaying message from {sender_id}: {e}")

    def disconnect(self):
        """
        Sends a 'Disconnected' command to the server, signaling this client's intention to leave.
        Sets the `disconnected` flag to True to stop communication threads.
        """
        logger.info("Sending disconnect command to server.")
        try:
            self.server_protocol.send_message(self.socket, self.id, 'Server', 'command', 'Disconnected')
            self.disconnected = True
            logger.info("Disconnect command sent. Client set to disconnected state.")
        except socket.error as e:
            logger.error(f"Socket error when sending disconnect command: {e}")
        except Exception as e:
            logger.error(f"Error sending disconnect command: {e}")

    def disconnect_response(self):
        """
        Handles the server's notification that another client has disconnected.
        Removes the disconnected client from internal lists and updates the GUI.
        """
        logger.info("Received notification of client disconnection.")
        try:
            message_dict = self.server_protocol.receive_message(self.socket)
            if not message_dict or 'data' not in message_dict:
                logger.warning("Received malformed disconnect client message.")
                return

            disconnect_id = self.server_protocol.decrypt_message(message_dict)
            # Assert that a valid ID was received
            assert disconnect_id is not None and disconnect_id != "", "Received empty disconnect ID."

            username = self.clients_usernames.get(disconnect_id, f"Unknown User ({disconnect_id})")
            logger.info(f"Client '{username}' (ID: {disconnect_id}) disconnected.")

            # Update GUI to remove the disconnected user
            self.gui.after(0, lambda u=username: self.gui.frames[ChatScreen].remove_active_user(u))

            # Remove disconnected client's data from internal state
            if disconnect_id in self.protocols:
                del self.protocols[disconnect_id]
            if disconnect_id in self.clients_ids:
                self.clients_ids.remove(disconnect_id)
            if disconnect_id in self.clients_usernames:
                self.clients_usernames.pop(disconnect_id)

        except socket.error as e:
            logger.error(f"Socket error during disconnect response: {e}")
        except Exception as e:
            logger.error(f"Error processing disconnect response: {e}")

    @staticmethod
    def basic_credentials_check(username, password):
        """
        Checks for basic validity of username and password.

        Returns:
            Tuple (bool, str): (True, "") if valid, otherwise (False, reason)
        """
        # Username checks
        if not username or not isinstance(username, str):
            return False, "Username must be a non-empty string."
        if len(username) < 3 or len(username) > 20:
            return False, "Username must be between 3 and 20 characters long."
        if not re.match(r"^[a-zA-Z0-9_.-]+$", username):
            return False, "Username can only contain letters, numbers, underscores, hyphens, and periods."

        # Password checks
        if not password or not isinstance(password, str):
            return False, "Password must be a non-empty string."
        if len(password) < 8:
            return False, "Password must be at least 8 characters long."
        if not re.search(r"[A-Z]", password):
            return False, "Password must contain at least one uppercase letter."
        if not re.search(r"[a-z]", password):
            return False, "Password must contain at least one lowercase letter."
        if not re.search(r"[0-9]", password):
            return False, "Password must contain at least one number."
        if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
            return False, "Password must contain at least one special character."

        return True, ""


if __name__ == '__main__':
    """
    Main execution block for the client application.
    Instantiates the Client and runs it. Includes basic error handling for the main loop.
    """
    client = None
    try:
        client = Client()
        client.run()
    except Exception as error:
        # Catch any unhandled exceptions from the client's main execution
        logger.critical(f"Client application encountered a critical unhandled error: {error}", exc_info=True)
    finally:
        if 'client' in locals() and client.socket:
            if not client.disconnected:
                logger.info("Attempting final socket close on unexpected exit.")
                try:
                    client.socket.close()
                except socket.error as error:
                    logger.error(f"Error closing socket during final cleanup: {error}")
        logger.info("Client application terminated.")
