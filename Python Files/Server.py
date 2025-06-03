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


logger = setup_logger()
logger.info("Server initialized.")


class Server:
    def __init__(self):
        self.socket = None                        # The main server listening socket
        self.clients_sockets = {}                 # Stores client sockets keyed by client ID
        self.clients_usernames = {}               # Stores client usernames keyed by client ID
        self.protocols = {}                       # Stores Protocol instances for each client keyed by client ID
        self.db = None                            # ClientDatabase instance for user authentication
        self.client_list_lock = threading.Lock()  # A lock to protect shared client lists
        self.threads = []                         # List to keep track of active client handler threads
        self.transfer_queue = queue.Queue()       # Queue for transferring AES keys during client join
        self.last_id = 0                          # Counter for assigning unique client IDs

    def run(self):
        """
        Starts the server: binds to a specific address and port, listens for
        incoming connections, and starts a new thread to handle each connected client.
        The server continues to accept connections until a KeyboardInterrupt (Ctrl+C).
        """
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            # Bind the socket to the local address and port
            server_socket.bind(('localhost', 8080))
            self.socket = server_socket
            logger.info("Server socket bound to ('localhost', 8080).")
            # Assert that the socket is bound and assigned
            assert self.socket is not None, "Server socket failed to bind."

            # Listen for incoming connections, with a backlog of 5 pending connections
            self.socket.listen(5)
            logger.info("Server is listening for incoming connections...")

            while True:
                # Accept a new client connection
                client_socket, addr = self.socket.accept()
                logger.info(f"Accepted connection from {addr}")

                # Start a new thread to handle this client
                thread = threading.Thread(target=self.handle_client, args=(client_socket,), daemon=True,
                                          name=f"ClientHandler-{addr}")
                thread.start()
                self.threads.append(thread)

        except socket.error as e:
            logger.critical(f"Socket error during server run: {e}")
        except KeyboardInterrupt:
            logger.info("\n[!] Server shutting down due to KeyboardInterrupt.")
        except Exception as e:
            logger.critical(f"An unexpected error occurred during server runtime: {e}")
        finally:
            logger.info("Closing all client sockets and server listening socket.")
            # Ensure all client sockets are closed gracefully
            with self.client_list_lock:
                for client_id, client_sock in list(self.clients_sockets.items()):  # Iterate over a copy
                    try:
                        self.disconnect_client(client_id, server_shutdown=True)  # Notify client and remove from lists
                    except Exception as e:
                        logger.error(f"Error during shutdown for client {client_id}: {e}")
                self.clients_sockets.clear()  # Clear the dictionary after attempting to close all

            # Close the main server listening socket
            if self.socket:
                try:
                    self.socket.close()
                    logger.info("Server listening socket closed.")
                except socket.error as e:
                    logger.error(f"Error closing server socket: {e}")

            # Optionally join client threads (can be problematic if they are blocked)
            # for thread in self.threads:
            #     if thread.is_alive():
            #         thread.join(timeout=1)
            logger.info("Server shutdown complete.")

    def handle_client(self, client_socket: socket.socket):
        """
        Handles communication with a single client throughout its session.
        This includes key exchange, ID assignment, authentication (login/signup),
        and then continuous message processing until the client disconnects.

        Args:
            client_socket (socket.socket): The socket object for the connected client.
        """
        current_client_id = None  # Initialize to None for error logging clarity
        try:
            client_protocol = Protocol(logger)
            logger.info(f"Handling new client connection from {client_socket.getpeername()}")

            # Step 1: Exchange RSA public key and provide AES key
            self.exchange_keys_with_client(client_socket, client_protocol)
            logger.debug("Key exchange with client completed.")

            # Step 2: Assign a unique client ID and send it to the client
            with self.client_list_lock:
                self.last_id += 1
                client_id = str(self.last_id)
                self.clients_sockets[client_id] = client_socket
                self.protocols[client_id] = client_protocol
            current_client_id = client_id  # Update for use in this method's scope
            logger.info(f"Assigned client ID: {client_id}")
            client_protocol.send_message(client_socket, 'Server', client_id, 'identification', client_id)
            # Assert that the client ID is added to protocols
            assert client_id in self.protocols, "Client protocol not added for new ID."

            # Step 3: Handle client authentication (Login/Signup)
            self.db = ClientDatabase()  # Connect to database
            username = None
            identified = False
            while not identified:
                message_dict = client_protocol.receive_message(client_socket)
                if message_dict is None:  # Client disconnected during authentication
                    logger.warning(f"Client {client_id} disconnected during authentication.")
                    break  # Exit loop and proceed to cleanup

                data = client_protocol.decrypt_message(message_dict)
                if not data:
                    logger.warning(f"Received empty authentication data from client {client_id}.")
                    client_protocol.send_message(client_socket, 'Server', client_id, 'status', 'Invalid')
                    continue  # Ask client to re-authenticate

                parsed_data = data.split(maxsplit=1)  # Split only on first space
                if len(parsed_data) != 2:
                    logger.warning(f"Malformed authentication data from client {client_id}: '{data}'")
                    client_protocol.send_message(client_socket, 'Server', client_id, 'status', 'Invalid')
                    continue

                username, password = parsed_data

                if message_dict.get('type') == 'login':
                    logger.info(f"Client {client_id} attempting login for user: {username}")
                    identified = self.db.verify(username, password)
                elif message_dict.get('type') == 'signup':
                    logger.info(f"Client {client_id} attempting signup for user: {username}")
                    identified = self.db.insert(username, password)
                else:
                    logger.warning(
                        f"Client {client_id} sent unknown message type during auth: {message_dict.get('type')}")

                if not identified:
                    logger.info(f"Authentication failed for user {username} (ID: {client_id}).")
                    client_protocol.send_message(client_socket, 'Server', client_id, 'status', 'Invalid')
                else:
                    logger.info(f"User {username} (ID: {client_id}) successfully authenticated.")
                    client_protocol.send_message(client_socket, 'Server', client_id, 'status', 'Confirmed')

            self.db.close()  # Close database connection after authentication attempt
            if not identified:
                logger.warning(f"Client {client_id} failed to authenticate and will be disconnected.")
                self.disconnect_client(client_id)  # Clean up if not identified
                return  # Exit handler thread

            # Step 4: Client successfully authenticated, add to active users and notify others
            with self.client_list_lock:
                self.clients_usernames[client_id] = username
            logger.info(f"Client {client_id} ({username}) is now fully connected.")

            # Initiate the new client join operation to synchronize other clients
            self.new_client_operation(client_socket, client_protocol, client_id, username)

            # Step 5: Main message processing loop
            disconnected = False
            while not disconnected:
                message_dict = client_protocol.receive_message(client_socket)
                if message_dict is None:
                    logger.info(f"Client {client_id} disconnected gracefully (received None message_dict).")
                    disconnected = True
                    break

                target = message_dict.get('target')
                message_type = message_dict.get('type')

                if target == 'Server':
                    data = client_protocol.decrypt_message(message_dict)
                    if message_type == 'alert':
                        if data == 'AES key incoming':
                            logger.debug(f"Client {client_id} sent AES key incoming alert.")
                            aes_dict = client_protocol.receive_aes_message(client_socket)
                            if aes_dict:
                                self.transfer_queue.put(aes_dict)
                            else:
                                logger.warning(f"Client {client_id} sent AES key alert but no AES key received.")
                    elif message_type == 'command':
                        if data == 'Disconnected':
                            logger.info(f"Client {client_id} sent 'Disconnected' command.")
                            self.disconnect_client(client_id)  # Initiate server-side disconnect
                            disconnected = True
                        else:
                            logger.warning(f"Unknown command '{data}' from client {client_id}.")
                    else:
                        logger.warning(
                            f"Unknown message type '{message_type}' targeted at Server from client {client_id}.")
                elif target in self.clients_sockets:  # Target is another client
                    # Assert that the target client exists before attempting transfer
                    assert target in self.protocols and target in self.clients_sockets, \
                        f"Target client {target} does not exist in active lists."
                    self.message_transfer_operation(client_id, message_dict)
                else:
                    logger.warning(f"Message from client {client_id} has invalid target: {target}.")

        except socket.error as e:
            logger.error(f"Socket error with client {current_client_id}: {e}")
        except Exception as e:
            logger.critical(f"An unexpected error occurred in client handler for {current_client_id}: {e}",
                            exc_info=True)
        finally:
            # Ensure client is removed from all lists upon thread exit
            if current_client_id in self.clients_sockets:
                logger.info(f"Cleaning up resources for client {current_client_id}.")
                # Ensure client is properly removed if thread exits unexpectedly
                self.disconnect_client(current_client_id,
                                       server_initiated=True)
            logger.info(f"Client handler thread for {current_client_id} exiting.")

    @staticmethod
    def exchange_keys_with_client(client_socket: socket.socket, protocol: Protocol):
        """
        Performs the RSA public key exchange with a newly connected client and
        sends back a new AES key encrypted with the client's public RSA key.

        Args:
            client_socket (socket.socket): The socket connected to the client.
            protocol (Protocol): The Protocol instance for this client.
        """
        logger.info(f"Starting key exchange with client {client_socket.getpeername()}.")
        try:
            # Receive client's public RSA key
            public_key_message = protocol.receive_public_rsa_key(client_socket)
            if not public_key_message or 'data' not in public_key_message or 'sender' not in public_key_message:
                raise ValueError("Did not receive valid public RSA key from client.")

            client_public_key = public_key_message['data']
            sender_placeholder = public_key_message['sender']  # This is 'no id' from client side

            # Generate a new AES key for this client
            protocol.aes.generate_key("my_secure_password")  # Use a password for consistent key derivation
            logger.debug(f"Generated AES key for client {client_socket.getpeername()}.")

            # Send the AES key encrypted with the client's public RSA key
            protocol.send_aes_key(client_socket, 'Server', sender_placeholder, client_public_key)
            logger.info(f"AES key sent to client {client_socket.getpeername()}.")
            # Assert that the AES key is set in the protocol
            assert protocol.aes.key is not None, "AES key not set in protocol after generation."
        except socket.error as e:
            logger.error(f"Socket error during key exchange with client {client_socket.getpeername()}: {e}")
            raise  # Re-raise to be handled by handle_client
        except ValueError as e:
            logger.error(f"Data error during key exchange with client {client_socket.getpeername()}: {e}")
            raise
        except Exception as e:
            logger.critical(
                f"An unexpected error occurred during key exchange with client {client_socket.getpeername()}: {e}")
            raise

    def new_client_operation(self, client_socket: socket.socket, client_protocol: Protocol, client_id: str,
                             username: str):
        """
        Manages the process of a newly authenticated client joining the chat network.
        It handles broadcasting the new client's presence to existing clients and
        facilitating the exchange of AES keys between the new client and existing ones.

        Args:
            client_socket (socket.socket): The socket of the new client.
            client_protocol (Protocol): The protocol instance for the new client.
            client_id (str): The unique ID of the new client.
            username (str): The username of the new client.
        """
        logger.info(f"Starting new client operation for client {client_id} ({username}).")
        try:
            # Receive the new client's public RSA key (which was broadcast by client initially)
            rsa_message_dict = client_protocol.receive_public_rsa_key(client_socket)
            if not rsa_message_dict or 'data' not in rsa_message_dict:
                raise ValueError(f"Failed to receive RSA public key from new client {client_id}.")

            # Inform the new client about the number of existing clients
            with self.client_list_lock:
                # Calculate number of other active clients (excluding self and any not yet fully setup)
                clients_amount = len(self.clients_usernames) - 1  # Subtract current client
            logger.debug(f"Notifying client {client_id} about {clients_amount} existing clients.")
            client_protocol.send_message(client_socket, 'Server', client_id, 'clients amount', str(clients_amount))
            # Assert that clients_amount is consistent
            assert clients_amount >= 0, "Clients amount should be non-negative."

            # Iterate through existing clients to facilitate key exchange and info sharing
            for temp_id, temp_socket in list(self.clients_sockets.items()):  # Iterate over a copy for safety
                if temp_id == client_id:
                    continue  # Skip the current new client itself

                # Only proceed if the client is fully identified and has a username
                if temp_id in self.clients_usernames and temp_id in self.protocols:
                    temp_protocol = self.protocols[temp_id]
                    temp_protocol.rsa.set_public_key(rsa_message_dict['data'])
                    logger.debug(f"Processing existing client {temp_id} for new client {client_id}.")

                    # Step 1: Existing client (temp_id) informs server it's preparing to receive new client's RSA key.
                    # This happens implicitly or through a command from server.
                    # The server sends the 'new client' command to existing clients.
                    temp_protocol.send_message(temp_socket, 'Server', temp_id, 'command', 'new client')
                    logger.debug(f"Sent 'new client' command to existing client {temp_id}.")

                    # Step 2: Server relays new client's public RSA key to existing client (temp_id)
                    # The existing client will then encrypt its AES key for the new client using this public key.
                    # This is the `public_key` argument in `send_public_rsa_key` from server's perspective.
                    temp_protocol.send_public_rsa_key(temp_socket, client_id, temp_id)
                    logger.debug(f"Relayed new client {client_id}'s RSA key to existing client {temp_id}.")

                    # Step 3: Server receives the AES key from the existing client (temp_id)
                    # (This AES key is encrypted by temp_id using new_client_rsa_public_key)
                    logger.debug(f"Waiting for AES key from existing client {temp_id} for new client {client_id}.")
                    aes_dict = self.transfer_queue.get(timeout=10)  # Get AES key from queue
                    if not aes_dict or 'data' not in aes_dict:
                        logger.warning(
                            f"Did not receive expected AES key from client {temp_id}. Skipping for {client_id}.")
                        continue  # Skip to next client if AES key transfer failed

                    encrypted_key = aes_dict['data']

                    # Step 4: Server relays the encrypted AES key to the new client (client_id)
                    # The new client will decrypt this using its own private RSA key.
                    client_protocol.send_aes_key(client_socket, temp_id, client_id,
                                                 None, True, encrypted_key)
                    logger.debug(f"Relayed encrypted AES key from {temp_id} to new client {client_id}.")

                    # Step 5: Server relays usernames to both clients
                    # Send new client's username to existing client
                    temp_protocol.send_message(temp_socket, 'Server', temp_id, 'username', username)
                    # Send existing client's username to new client
                    client_protocol.send_message(client_socket, 'Server', client_id,
                                                 'username', self.clients_usernames[temp_id])
                    logger.debug(f"Exchanged usernames between {client_id} and {temp_id}.")
                else:
                    logger.warning(f"Skipping client {temp_id} in new_client_operation as not fully initialized.")

        except queue.Empty:
            logger.error(f"Timeout waiting for AES key in new_client_operation for client {client_id}.")
        except socket.error as e:
            logger.error(f"Socket error during new client operation for client {client_id}: {e}")
        except ValueError as e:
            logger.error(f"Data error during new client operation for client {client_id}: {e}")
        except Exception as e:
            logger.critical(f"An unexpected error occurred during new client operation for client {client_id}: {e}")
        logger.info(f"New client operation for client {client_id} finished.")

    def message_transfer_operation(self, sender_id: str, message_dict: dict):
        """
        Transfers a chat message from the sender to the intended recipient client.

        Args:
            sender_id (str): The ID of the client sending the message.
            message_dict (dict): The dictionary containing the encrypted message and its target.
        """
        target_id = message_dict.get('target')
        if not target_id:
            logger.warning(f"Message from {sender_id} has no target specified.")
            return

        logger.info(f"Transferring message from {sender_id} to {target_id}.")
        try:
            with self.client_list_lock:
                if target_id not in self.protocols or target_id not in self.clients_sockets:
                    logger.warning(f"Target client {target_id} not found in "
                                   f"active clients for message from {sender_id}. Message dropped.")
                    # Optionally, send an error back to sender
                    return

                target_protocol = self.protocols[target_id]
                target_socket = self.clients_sockets[target_id]

            # Relay the encrypted message as-is to the target client
            # The 'data' field in message_dict is already encrypted by the sender's protocol
            # with the target's AES key. So, just forward it.
            # The `is_encrypted=True` and `encrypted_data=message_dict['data']` tell `send_message`
            # to not encrypt the data again, but just send the provided encrypted data.
            target_protocol.send_message(target_socket, sender_id,
                                         target_id, 'message', message_dict['data'], True)
            logger.debug(f"Message from {sender_id} successfully relayed to {target_id}.")
        except socket.error as e:
            logger.error(f"Socket error during message transfer from {sender_id} to {target_id}: {e}")
            # Consider marking target_id as disconnected if continuous errors
        except Exception as e:
            logger.error(f"An error occurred during message transfer from {sender_id} to {target_id}: {e}")

    def disconnect_client(self, client_id: str, server_initiated: bool = False, server_shutdown: bool = False):
        """
        Manages the disconnection of a client from the server.
        Notifies other clients, removes the client's data from server lists, and closes its socket.

        Args:
            client_id (str): The ID of the client to disconnect.
            server_initiated (bool): True if the server initiated the disconnect (e.g., due to an error).
            server_shutdown (bool): True if the server is shutting down.
        """
        logger.info(f"Initiating disconnect for client {client_id}. "
                    f"Server initiated: {server_initiated}, Server shutdown: {server_shutdown}.")

        if client_id not in self.clients_sockets:
            logger.warning(f"Attempted to disconnect non-existent client ID: {client_id}.")
            return

        client_socket_to_close = None
        with self.client_list_lock:
            # Remove client from active lists first to prevent new operations on it
            if client_id in self.protocols:
                self.protocols.pop(client_id)
            if client_id in self.clients_usernames:
                self.clients_usernames.pop(client_id)
            if client_id in self.clients_sockets:
                client_socket_to_close = self.clients_sockets.pop(client_id)
            logger.debug(f"Client {client_id} removed from server's internal lists.")

        # Notify the client itself to disconnect if not server shutdown
        if not server_shutdown and server_initiated and client_socket_to_close:
            try:
                # Use a temporary protocol for the last message if the main one was already removed
                temp_protocol = Protocol(logger)  # Create a transient protocol for sending the final command
                temp_protocol.send_message(client_socket_to_close, 'Server', client_id, 'command', 'Disconnect')
                logger.info(f"Sent 'Disconnect' command to client {client_id}.")
            except socket.error as e:
                logger.error(f"Error sending final disconnect command to client {client_id}: {e}")
            except Exception as e:
                logger.error(f"Unexpected error when sending final disconnect command to client {client_id}: {e}")
            finally:
                if client_socket_to_close:
                    try:
                        client_socket_to_close.shutdown(socket.SHUT_RDWR)
                    except OSError as e:  # Socket might already be closed or in bad state
                        logger.warning(f"Error during socket shutdown for {client_id}: {e}")
                    client_socket_to_close.close()
                    logger.info(f"Socket for client {client_id} closed.")

        # Notify all other active clients about this client's disconnection
        for temp_id, temp_socket in list(self.clients_sockets.items()):  # Iterate over a copy
            if temp_id in self.protocols:  # Ensure protocol exists
                temp_protocol = self.protocols[temp_id]
                try:
                    temp_protocol.send_message(temp_socket, 'Server', temp_id, 'command', 'disconnect client')
                    temp_protocol.send_message(temp_socket, 'Server', temp_id, 'disconnect id', client_id)
                    logger.debug(f"Notified client {temp_id} about disconnection of {client_id}.")
                except socket.error as e:
                    logger.error(f"Socket error notifying client {temp_id} about {client_id} disconnection: {e}")
                    # Consider this client also disconnected if it fails
                except Exception as e:
                    logger.error(f"Error notifying client {temp_id} about {client_id} disconnection: {e}")

        # Final close of the socket if it hasn't been closed already
        # Only close if client initiated and socket wasn't closed by server_initiated block
        if not server_initiated and client_socket_to_close:
            try:
                client_socket_to_close.shutdown(socket.SHUT_RDWR)
            except OSError as e:
                logger.warning(f"Error during socket shutdown for {client_id} (client initiated): {e}")
            client_socket_to_close.close()
            logger.info(f"Socket for client {client_id} closed (client initiated).")

        logger.info(f"Client {client_id} successfully disconnected.")


if __name__ == '__main__':
    """
    Main execution block for the server application.
    Instantiates the Server and runs it, providing basic error handling for the main loop.
    """
    try:
        server = Server()
        server.run()
    except Exception as error:
        # Catch any unhandled exceptions from the server's main execution
        logger.critical(f"Server application encountered a critical unhandled error: {error}", exc_info=True)
    finally:
        # Final cleanup or status logging after server run
        # The run() method's finally block should handle most socket closures.
        logger.info("Server application terminated.")
