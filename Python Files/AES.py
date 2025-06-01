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
    handler = logging.FileHandler(log_file, mode='w')
    formatter = logging.Formatter('%(levelname)s: %(message)s')
    handler.setFormatter(formatter)

    logger = logging.getLogger(name)
    logger.setLevel(level)
    if not logger.hasHandlers():
        logger.addHandler(handler)
    return logger

logger = setup_logger('AES', os.path.join(FILE_PATH_LOGS_FOLDER, 'AES.log'))

class AES:
    def __init__(self, generator, key: bytes = None):
        self.generator = generator
        self.key = key
        logger.info('AES instance created')

    def set_key(self, new_key: bytes):
        if len(new_key) != 32:
            logger.error("Invalid key length attempted to set")
            raise ValueError("Key must be exactly 32 bytes (256-bit).")
        self.key = new_key
        logger.info("AES key updated")

    def generate_key(self, password: str, salt: bytes = None) -> tuple:
        if salt is None:
            salt = self.generator.generate_int(128).to_bytes(16, 'big')
        key = PBKDF2(password, salt, dkLen=32)
        self.key = key
        logger.info("AES key generated from password")
        return key, salt

    def encrypt(self, plaintext: str) -> str:
        if self.key is None:
            logger.error("Attempted encryption without key set")
            raise ValueError("Encryption key is not set.")

        nonce = self.generator.generate_int(128).to_bytes(16, 'big')
        cipher = CryptoAES.new(self.key, CryptoAES.MODE_GCM, nonce=nonce)
        ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode())
        encrypted_data = nonce + tag + ciphertext
        logger.debug(f"Encrypted plaintext of length {len(plaintext)} bytes to {len(encrypted_data)} bytes ciphertext")
        encrypted_text = base64.b64encode(encrypted_data).decode()
        return encrypted_text

    def decrypt(self, encrypted_text: str) -> str:
        if self.key is None:
            logger.error("Attempted decryption without key set")
            raise ValueError("Decryption key is not set.")

        encrypted_data = base64.b64decode(encrypted_text)
        nonce, tag, ciphertext = encrypted_data[:16], encrypted_data[16:32], encrypted_data[32:]
        cipher = CryptoAES.new(self.key, CryptoAES.MODE_GCM, nonce=nonce)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        logger.debug(f"Decrypted ciphertext of length {len(encrypted_data)} bytes")
        return plaintext.decode()


if __name__ == '__main__':
    # Initialize RNG
    rng = Generator()

    # Create AES helper with RNG
    aes = AES(rng)

    # Generate a key from a password
    key, salt = aes.generate_key("my_secure_password")
    print(type(key))
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