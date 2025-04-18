"""
Author: Tomer Meskin
Date: 21/03/2025

Description: RSA class that allows encryption and decryption of
data using no RSA library, supports external public keys.
"""

import logging
import os
import hashlib
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


logger = setup_logger('RSA', os.path.join(FILE_PATH_LOGS_FOLDER, 'RSA.log'))


class RSA:
    def __init__(self, generator=None, key_size=1024):
        self.generator = generator
        self.key_size = key_size
        self.public_key = None
        self.private_key = None

        logger.info('Instance created')

    @staticmethod
    def gcd(a, b):
        """
        Compute the Greatest Common Divisor (GCD) using Euclid's algorithm
        :param a:
        :param b:
        """
        while b:
            a, b = b, a % b
        return a

    @staticmethod
    def mod_inverse(e, phi):
        # Compute modular inverse of e (mod phi) using the Extended Euclidean Algorithm
        def egcd(a, b):
            if a == 0:
                return b, 0, 1
            g, x, y = egcd(b % a, a)
            return g, y - (b // a) * x, x

        g, x, _ = egcd(e, phi)
        if g != 1:
            raise ValueError("Modular inverse does not exist")
        return x % phi

    def generate_keys(self):
        # Generate RSA public and private key pairs
        if not self.generator:
            raise ValueError("Generator is not initialized")
        p = self.generator.generate_prime(self.key_size // 2)
        q = self.generator.generate_prime(self.key_size // 2)
        n = p * q
        phi = (p - 1) * (q - 1)

        # Choose e such that 1 < e < phi and gcd(e, phi) = 1
        e = 65537  # Commonly used public exponent
        if self.gcd(e, phi) != 1:
            raise ValueError("Chosen e is not coprime with phi, choose a different e")

        d = self.mod_inverse(e, phi)

        self.public_key = (n, e)
        self.private_key = (n, d)

        logger.debug("Generated public and private keys")
        return self.public_key, self.private_key

    def set_public_key(self, public_key):
        """Set the public key from an external source."""
        self.public_key = public_key
        logger.debug(f'Set public key: {public_key}')

    def encrypt(self, message, external_public_key=None):
        """Encrypt a message using the public key."""
        public_key = external_public_key or self.public_key
        if not public_key:
            raise ValueError("Public key not available")

        n, e = public_key
        if isinstance(message, bytes):
            message_int = int.from_bytes(message, 'big')  # Directly use bytes if the message is in bytes
        else:
            message_int = int.from_bytes(message.encode(), 'big')  # Otherwise, encode the string message

        cipher_int = pow(message_int, e, n)

        logger.debug(f"""Encrypted message: {message}
       Into: {cipher_int}""")
        return cipher_int

    def decrypt(self, ciphertext):
        # Decrypt a ciphertext using the private key
        if not self.private_key:
            raise ValueError("Private key not generated")

        n, d = self.private_key
        message_int = pow(ciphertext, d, n)

        message = message_int.to_bytes((message_int.bit_length() + 7) // 8, 'big')

        logger.debug(f"""Decrypted message: {ciphertext}
       Into: {message}""")
        return message

    def sign(self, message):
        # Sign a message using the private key
        if not self.private_key:
            raise ValueError("Private key not generated")

        n, d = self.private_key
        hash_value = int.from_bytes(hashlib.sha256(message.encode()).digest(), 'big')
        signature = pow(hash_value, d, n)

        logger.debug(f'Generated signature: {signature}')
        return signature

    def verify(self, message, signature, external_public_key=None):
        """Verify a signature using the public key."""
        public_key = external_public_key or self.public_key
        if not public_key:
            raise ValueError("Public key not available")

        n, e = public_key
        hash_value = int.from_bytes(hashlib.sha256(message.encode()).digest(), 'big')
        decrypted_hash = pow(signature, e, n)

        logger.debug(f'Verified signature: {hash_value == decrypted_hash}')
        return hash_value == decrypted_hash


if __name__ == '__main__':
    if __name__ == '__main__':
        prime_generator = Generator()
        rsa_self = RSA(prime_generator, key_size=1024)
        rsa_self.generate_keys()
        print(type(rsa_self.public_key[0]), type(rsa_self.public_key[1]))
        # Example 1: Sending a message to someone with their public key
        someone_public_key = (
                    rsa_self.public_key[0], rsa_self.public_key[1])  # replace with the actual public key received.
        message_to_send = "Secret message for someone"
        encrypted_message = rsa_self.encrypt(message_to_send, external_public_key=someone_public_key)
        print(f"Encrypted message for someone: {encrypted_message}")

        # Example 2: Decrypting a message encrypted with your public key
        message_from_someone = "Another secret message"
        # simulate someone encrypting with our public key.
        encrypted_from_someone = rsa_self.encrypt(message_from_someone,
                                                  external_public_key=rsa_self.public_key)
        decrypted_from_someone = rsa_self.decrypt(encrypted_from_someone)
        print(f"Decrypted message from someone: {decrypted_from_someone}")
