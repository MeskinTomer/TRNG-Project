"""
Author: Tomer Meskin
Date: 23/03/2025

Description: AES class that allows encryption and decryption of
data using an AES library, supports external public keys.
"""

import logging
import os
from Crypto.Cipher import AES as CryptoAES
from Crypto.Protocol.KDF import PBKDF2
import base64
from Generator import Generator

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


logger = setup_logger('AES', os.path.join(FILE_PATH_LOGS_FOLDER, 'AES.log'))


class AES:
    def __init__(self, generator, key: bytes = None):
        """
        Initialize AES with a custom RNG and optional key.
        :param generator: Instance of Generator class for true randomness.
        :param key: Optional 256-bit encryption key.
        """
        self.generator = generator  # Use custom Generator for randomness
        self.key = key  # Set key if provided (must be 32 bytes for AES-256)

        logger.info('Instance created')

    def set_key(self, new_key: bytes):
        """Update the encryption key using Generator."""
        if len(new_key) != 32:
            raise ValueError("Key must be exactly 32 bytes (256-bit).")
        self.key = new_key

    def generate_key(self, password: str, salt: bytes = None) -> tuple:
        """
        Generate a 256-bit key using PBKDF2 and custom RNG for salt.
        :param password: Password to derive the key.
        :param salt: Optional salt. If None, a new salt is generated.
        :return: Tuple of (key, salt)
        """
        if salt is None:
            salt = self.generator.generate_int(128).to_bytes(16, 'big')  # Generate salt using Generator
        key = PBKDF2(password, salt, dkLen=32)  # Derive a 256-bit key
        self.key = key  # Store the key

        logger.debug(f'Generated encryption key: {key}')
        return key, salt

    def encrypt(self, plaintext: str) -> str:
        """
        Encrypt a message using AES-GCM and return a base64-encoded string.
        :param plaintext: The text to encrypt.
        :return: Base64-encoded ciphertext.
        """
        if self.key is None:
            raise ValueError("Encryption key is not set.")

        nonce = self.generator.generate_int(128).to_bytes(16, 'big')  # Generate nonce using Generator
        cipher = CryptoAES.new(self.key, CryptoAES.MODE_GCM, nonce=nonce)
        ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode())

        # Store nonce, tag, and ciphertext
        encrypted_data = nonce + tag + ciphertext

        logger.debug(f"""Encrypted message: {plaintext}
       Into: {encrypted_data}""")
        return base64.b64encode(encrypted_data).decode()

    def decrypt(self, encrypted_text: str) -> str:
        """
        Decrypt a base64-encoded AES-GCM ciphertext.
        :param encrypted_text: Base64-encoded encrypted data.
        :return: Decrypted plaintext.
        """
        if self.key is None:
            raise ValueError("Decryption key is not set.")

        encrypted_data = base64.b64decode(encrypted_text)

        # Extract nonce, tag, and ciphertext
        nonce, tag, ciphertext = encrypted_data[:16], encrypted_data[16:32], encrypted_data[32:]

        cipher = CryptoAES.new(self.key, CryptoAES.MODE_GCM, nonce=nonce)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)

        logger.debug(f"""Decrypted message: {encrypted_text}
       Into: {plaintext}""")
        return plaintext.decode()


if __name__ == '__main__':
    # Initialize RNG
    rng = Generator()

    # Create AES helper with RNG
    aes = AES(rng)

    # Generate a key from a password
    key, salt = aes.generate_key("my_secure_password")

    # Encrypt a message
    encrypted_message = aes.encrypt("Hello, this is a secret!")
    print("Encrypted:", encrypted_message)

    # Decrypt the message
    decrypted_message = aes.decrypt(encrypted_message)
    print("Decrypted:", decrypted_message)

    # Update the key manually
    new_key = rng.generate_int(256).to_bytes(32, 'big')  # Generate a fresh 256-bit key
    aes.set_key(new_key)

    # Encrypt with the new key
    new_encrypted = aes.encrypt("New message with new key!")
    print("New Encrypted:", new_encrypted)