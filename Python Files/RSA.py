"""
Author: Tomer Meskin
Date: 21/03/2025

Description: RSA class that allows encryption and decryption of
data using no RSA library. It supports both key generation and using external public keys.
"""

import logging
import os
import hashlib
from Generator import Generator

FILE_PATH_LOGS_FOLDER = os.path.join(os.path.dirname(__file__), '..', 'Log Files')


def setup_logger(name, log_file, level=logging.DEBUG):
    """Sets up a logger with file output."""
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
        """
        Initialize the RSA instance.
        :param generator: An instance of Generator to provide random primes.
        :param key_size: Desired RSA key size in bits.
        """
        self.generator = generator
        self.key_size = key_size
        self.public_key = None
        self.private_key = None
        logger.info('RSA instance created')

    @staticmethod
    def gcd(a, b):
        """Compute the greatest common divisor using Euclidean algorithm."""
        while b:
            a, b = b, a % b
        return a

    @staticmethod
    def mod_inverse(e, phi):
        """
        Compute the modular inverse of e modulo phi using the Extended Euclidean Algorithm.
        Finds d such that (d * e) % phi == 1
        """
        def egcd(a, b):
            if a == 0:
                return b, 0, 1
            g, x, y = egcd(b % a, a)
            return g, y - (b // a) * x, x

        g, x, _ = egcd(e, phi)
        if g != 1:
            logger.error("Modular inverse does not exist for given values")
            raise ValueError("Modular inverse does not exist")

        return x % phi

    def generate_keys(self):
        if not self.generator:
            logger.error("Generator not initialized for key generation")
            raise ValueError("Generator is not initialized")

        try:
            p = self.generator.generate_prime(self.key_size // 2)
            q = self.generator.generate_prime(self.key_size // 2)

            assert p != q, "Generated primes p and q must be distinct"
            n = p * q
            phi = (p - 1) * (q - 1)

            e = 65537
            assert self.gcd(e, phi) == 1, "e must be coprime with phi"

            d = self.mod_inverse(e, phi)
            assert pow(pow(42, e, n), d, n) == 42, "RSA keypair invalid (encryption/decryption failed)"

            self.public_key = (n, e)
            self.private_key = (n, d)

            logger.info("RSA keys generated successfully")
            return self.public_key, self.private_key

        except AssertionError as ae:
            logger.exception("Assertion failed during key generation")
            raise
        except Exception as e:
            logger.exception("Unexpected error during RSA key generation")
            raise

    def set_public_key(self, public_key):
        """
        Sets the public key externally (for encryption/verification).
        :param public_key: Tuple (n, e)
        """
        self.public_key = public_key
        logger.info(f'Set external public key: {public_key}')

    def encrypt(self, message, external_public_key=None):
        public_key = external_public_key or self.public_key
        if not public_key:
            logger.error("Public key not available for encryption")
            raise ValueError("Public key not available")

        try:
            n, e = public_key
            assert isinstance(n, int) and isinstance(e, int), "Public key must be integers"

            if isinstance(message, bytes):
                message_int = int.from_bytes(message, 'big')
            else:
                message_int = int.from_bytes(message.encode(), 'big')

            assert message_int < n, "Message too large to encrypt with current RSA modulus"

            cipher_int = pow(message_int, e, n)
            logger.debug(f'Encrypted message of length {len(str(cipher_int))} digits')
            return cipher_int

        except AssertionError as ae:
            logger.exception("Assertion failed during encryption")
            raise
        except Exception as e:
            logger.exception("Unexpected error during encryption")
            raise

    def decrypt(self, ciphertext):
        if not self.private_key:
            logger.error("Private key not available for decryption")
            raise ValueError("Private key not generated")

        try:
            n, d = self.private_key
            assert isinstance(ciphertext, int), "Ciphertext must be an integer"

            message_int = pow(ciphertext, d, n)
            message = message_int.to_bytes((message_int.bit_length() + 7) // 8, 'big')
            logger.debug(f'Decrypted ciphertext of length {len(str(ciphertext))} digits')
            return message

        except AssertionError as ae:
            logger.exception("Assertion failed during decryption")
            raise
        except Exception as e:
            logger.exception("Unexpected error during decryption")
            raise

    def sign(self, message):
        if not self.private_key:
            logger.error("Private key not available for signing")
            raise ValueError("Private key not generated")

        try:
            assert isinstance(message, str), "Message to sign must be a string"
            n, d = self.private_key
            hash_value = int.from_bytes(hashlib.sha256(message.encode()).digest(), 'big')
            signature = pow(hash_value, d, n)
            logger.info('Message signed successfully')
            return signature

        except AssertionError as ae:
            logger.exception("Assertion failed during signing")
            raise
        except Exception as e:
            logger.exception("Unexpected error during signing")
            raise

    def verify(self, message, signature, external_public_key=None):
        public_key = external_public_key or self.public_key
        if not public_key:
            logger.error("Public key not available for signature verification")
            raise ValueError("Public key not available")

        try:
            assert isinstance(message, str), "Message to verify must be a string"
            assert isinstance(signature, int), "Signature must be an integer"

            n, e = public_key
            hash_value = int.from_bytes(hashlib.sha256(message.encode()).digest(), 'big')
            decrypted_hash = pow(signature, e, n)
            verified = hash_value == decrypted_hash
            logger.info(f'Signature verification result: {verified}')
            return verified

        except AssertionError as ae:
            logger.exception("Assertion failed during verification")
            raise
        except Exception as e:
            logger.exception("Unexpected error during signature verification")
            raise


if __name__ == '__main__':
    # Example: Key generation and encryption/decryption
    prime_generator = Generator()
    rsa_self = RSA(prime_generator, key_size=1024)
    public_key, private_key = rsa_self.generate_keys()

    # Encrypting a message using the public key
    message = "Confidential message"
    ciphertext = rsa_self.encrypt(message)
    print("Encrypted:", ciphertext)

    # Decrypting with private key
    decrypted = rsa_self.decrypt(ciphertext)
    print("Decrypted:", decrypted.decode())

    # Signing the message
    signature = rsa_self.sign(message)
    print("Signature:", signature)

    # Verifying the signature
    is_valid = rsa_self.verify(message, signature)
    print("Signature valid:", is_valid)
