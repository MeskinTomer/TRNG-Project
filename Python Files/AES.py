"""
Author: Tomer Meskin
Date: 23/03/2025

Description:
AES encryption and decryption class using the PyCrypto dome library.
Includes key generation via PBKDF2, manual key setting, and support for
GCM mode with nonce and authentication tag. Uses custom randomness
source for nonce generation.

This class logs all major operations and exceptions for traceability.
"""

import logging
import os
from Crypto.Cipher import AES as CryptoAES
from Crypto.Protocol.KDF import PBKDF2
import base64
from Generator import Generator

# Path to log directory
FILE_PATH_LOGS_FOLDER = os.path.join(os.path.dirname(__file__), '..', 'Log Files')


def setup_logger(name, log_file, level=logging.DEBUG):
    """Initializes and returns a logger with the given name and file path."""
    handler = logging.FileHandler(log_file, mode='w')
    formatter = logging.Formatter('%(levelname)s: %(message)s')
    handler.setFormatter(formatter)

    temp_logger = logging.getLogger(name)
    temp_logger.setLevel(level)
    if not temp_logger.hasHandlers():
        temp_logger.addHandler(handler)
    return temp_logger


# Set up logger for AES operations
logger = setup_logger('AES', os.path.join(FILE_PATH_LOGS_FOLDER, 'AES.log'))


class AES:
    def __init__(self, generator: Generator, key: bytes = None):
        """
        Initialize the AES helper with an optional key and a randomness generator.

        :param generator: Instance of Generator for nonce creation.
        :param key: Optional 32-byte AES key.
        """
        self.generator = generator
        self.key = key
        logger.info('AES instance created')

    def set_key(self, new_key: bytes):
        """
        Set a new AES key manually.

        :param new_key: A 32-byte key (256-bit).
        """
        try:
            assert isinstance(new_key, bytes), "Key must be of type bytes"
            assert len(new_key) == 32, "Key must be exactly 32 bytes (256-bit)"
            self.key = new_key
            logger.info("AES key updated successfully")
        except AssertionError as ae:
            logger.exception("Invalid key provided to set_key()")
            raise ValueError(str(ae))
        except Exception as e:
            logger.exception(f"Unexpected error in set_key(): {e}")
            raise

    def generate_key(self, password: str, salt: bytes = None) -> tuple:
        """
        Generate a 256-bit key from a password using PBKDF2.

        :param password: Password to derive the key from.
        :param salt: Optional 16-byte salt. If not given, generated randomly.
        :return: Tuple of (key, salt).
        """
        try:
            assert isinstance(password, str), "Password must be a string"
            if salt is None:
                salt = self.generator.generate_int(128).to_bytes(16, 'big')
            assert isinstance(salt, bytes) and len(salt) == 16, "Salt must be 16 bytes"

            key = PBKDF2(password, salt, dkLen=32)  # Derive 256-bit key
            self.key = key
            logger.info("AES key generated from password")
            return key, salt
        except AssertionError as ae:
            logger.exception("Assertion failed during key generation")
            raise ValueError(str(ae))
        except Exception as e:
            logger.exception(f"Unexpected error in generate_key(): {e}")
            raise

    def encrypt(self, plaintext: str) -> str:
        """
        Encrypt a plaintext string using AES-GCM.

        :param plaintext: The string to encrypt.
        :return: Base64-encoded string of encrypted data (nonce + tag + ciphertext).
        """
        if self.key is None:
            logger.error("Attempted encryption without key set")
            raise ValueError("Encryption key is not set.")

        try:
            assert isinstance(plaintext, str), "Plaintext must be a string"

            nonce = self.generator.generate_int(128).to_bytes(16, 'big')
            assert isinstance(nonce, bytes) and len(nonce) == 16, "Nonce must be 16 bytes"

            cipher = CryptoAES.new(self.key, CryptoAES.MODE_GCM, nonce=nonce)
            ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode())

            encrypted_data = nonce + tag + ciphertext
            encrypted_text = base64.b64encode(encrypted_data).decode()

            logger.debug(f"Encrypted {len(plaintext)}-byte plaintext to {len(encrypted_data)}-byte ciphertext")
            return encrypted_text

        except AssertionError as ae:
            logger.exception("Assertion failed during encryption")
            raise ValueError(str(ae))
        except Exception as e:
            logger.exception(f"Unexpected error during encryption: {e}")
            raise

    def decrypt(self, encrypted_text: str) -> str:
        """
        Decrypt a base64-encoded ciphertext encrypted with AES-GCM.

        :param encrypted_text: Base64-encoded string containing nonce + tag + ciphertext.
        :return: Decrypted plaintext string.
        """
        if self.key is None:
            logger.error("Attempted decryption without key set")
            raise ValueError("Decryption key is not set.")

        try:
            assert isinstance(encrypted_text, str), "Encrypted text must be a base64 string"

            encrypted_data = base64.b64decode(encrypted_text)
            assert len(encrypted_data) >= 32, "Invalid encrypted data length"

            nonce, tag, ciphertext = encrypted_data[:16], encrypted_data[16:32], encrypted_data[32:]
            cipher = CryptoAES.new(self.key, CryptoAES.MODE_GCM, nonce=nonce)
            plaintext = cipher.decrypt_and_verify(ciphertext, tag)

            logger.debug(f"Decrypted ciphertext of length {len(encrypted_data)} bytes")
            return plaintext.decode()

        except AssertionError as ae:
            logger.exception("Assertion failed during decryption")
            raise ValueError(str(ae))
        except (ValueError, KeyError):
            logger.exception("Decryption failed: possible tampering or wrong key")
            raise ValueError("Decryption failed: invalid key or corrupted data.")
        except Exception as e:
            logger.exception(f"Unexpected error during decryption: {e}")
            raise


if __name__ == '__main__':
    # Example usage for testing
    rng = Generator()
    aes = AES(rng)

    # Generate a key from a password
    temp_key, temp_salt = aes.generate_key("my_secure_password")
    print(f"Key type: {type(temp_key)}")

    # Encrypt a message
    encrypted_message = aes.encrypt("Hello, this is a secret!")
    print("Encrypted:", encrypted_message)

    # Decrypt the message
    decrypted_message = aes.decrypt(encrypted_message)
    print("Decrypted:", decrypted_message)

    # Manually set a new 256-bit key
    new_temp_key = rng.generate_int(256).to_bytes(32, 'big')
    aes.set_key(new_temp_key)

    # Encrypt again with the new key
    new_encrypted = aes.encrypt("New message with new key!")
    print("New Encrypted:", new_encrypted)
