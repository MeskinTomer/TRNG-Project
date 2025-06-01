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
    handler = logging.FileHandler(log_file, mode='w')
    formatter = logging.Formatter('%(levelname)s: %(message)s')
    handler.setFormatter(formatter)

    logger = logging.getLogger(name)
    logger.setLevel(level)
    if not logger.hasHandlers():
        logger.addHandler(handler)
    return logger


logger = setup_logger('RSA', os.path.join(FILE_PATH_LOGS_FOLDER, 'RSA.log'))


class RSA:
    def __init__(self, generator=None, key_size=1024):
        self.generator = generator
        self.key_size = key_size
        self.public_key = None
        self.private_key = None
        logger.info('RSA instance created')

    @staticmethod
    def gcd(a, b):
        while b:
            a, b = b, a % b
        return a

    @staticmethod
    def mod_inverse(e, phi):
        def egcd(a, b):
            if a == 0:
                return b, 0, 1
            g, x, y = egcd(b % a, a)
            return g, y - (b // a) * x, x

        g, x, _ = egcd(e, phi)
        if g != 1:
            logger.error("Modular inverse does not exist for given values")
            raise ValueError("Modular inverse does not exist")

        d = x % phi
        return d

    def generate_keys(self):
        if not self.generator:
            logger.error("Generator not initialized for key generation")
            raise ValueError("Generator is not initialized")
        p = self.generator.generate_prime(self.key_size // 2)
        q = self.generator.generate_prime(self.key_size // 2)
        n = p * q
        phi = (p - 1) * (q - 1)

        e = 65537
        if self.gcd(e, phi) != 1:
            logger.error("Public exponent e is not coprime with phi")
            raise ValueError("Chosen e is not coprime with phi")

        d = self.mod_inverse(e, phi)
        self.public_key = (n, e)
        self.private_key = (n, d)

        logger.info("RSA keys generated successfully")
        return self.public_key, self.private_key

    def set_public_key(self, public_key):
        self.public_key = public_key
        logger.info(f'Set external public key: {public_key}')

    def encrypt(self, message, external_public_key=None):
        public_key = external_public_key or self.public_key
        if not public_key:
            logger.error("Public key not available for encryption")
            raise ValueError("Public key not available")

        n, e = public_key
        if isinstance(message, bytes):
            message_int = int.from_bytes(message, 'big')
        else:
            message_int = int.from_bytes(message.encode(), 'big')

        cipher_int = pow(message_int, e, n)
        logger.debug(f'Encrypted message of length {len(str(cipher_int))} digits')
        return cipher_int

    def decrypt(self, ciphertext):
        if not self.private_key:
            logger.error("Private key not available for decryption")
            raise ValueError("Private key not generated")

        n, d = self.private_key
        message_int = pow(ciphertext, d, n)
        message = message_int.to_bytes((message_int.bit_length() + 7) // 8, 'big')
        logger.debug(f'Decrypted ciphertext of length {len(str(ciphertext))} digits')
        return message

    def sign(self, message):
        if not self.private_key:
            logger.error("Private key not available for signing")
            raise ValueError("Private key not generated")

        n, d = self.private_key
        hash_value = int.from_bytes(hashlib.sha256(message.encode()).digest(), 'big')
        signature = pow(hash_value, d, n)
        logger.info('Message signed successfully')
        return signature

    def verify(self, message, signature, external_public_key=None):
        public_key = external_public_key or self.public_key
        if not public_key:
            logger.error("Public key not available for signature verification")
            raise ValueError("Public key not available")

        n, e = public_key
        hash_value = int.from_bytes(hashlib.sha256(message.encode()).digest(), 'big')
        decrypted_hash = pow(signature, e, n)
        verified = hash_value == decrypted_hash
        logger.info(f'Signature verification result: {verified}')
        return verified


if __name__ == '__main__':
    if __name__ == '__main__':
        # prime_generator = Generator()
        # rsa_self = RSA(prime_generator, key_size=1024)
        # rsa_self.generate_keys()
        # print(type(rsa_self.public_key[0]), type(rsa_self.public_key[1]))
        # # Example 1: Sending a message to someone with their public key
        # someone_public_key = (
        #             rsa_self.public_key[0], rsa_self.public_key[1])  # replace with the actual public key received.
        # message_to_send = "Secret message for someone"
        # encrypted_message = rsa_self.encrypt(message_to_send, external_public_key=someone_public_key)
        # print(f"Encrypted message for someone: {encrypted_message}")
        #
        # # Example 2: Decrypting a message encrypted with your public key
        # message_from_someone = "Another secret message"
        # # simulate someone encrypting with our public key.
        # encrypted_from_someone = rsa_self.encrypt(message_from_someone,
        #                                           external_public_key=rsa_self.public_key)
        # decrypted_from_someone = rsa_self.decrypt(encrypted_from_someone)
        # print(f"Decrypted message from someone: {decrypted_from_someone}")

        prime_generator = Generator()
        rsa_self = RSA(prime_generator, key_size=1024)

