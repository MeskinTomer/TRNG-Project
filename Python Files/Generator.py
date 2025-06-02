"""
Author: Tomer Meskin
Date: 08/03/2025

Description: The Generator used for creating truly random numbers using
a picture captured by the camera, used for encryption
"""

import logging
import cv2
import math
import hashlib
import os
import random
from filelock import FileLock

LOCK_FILE = 'camera.lock'  # Lock file to serialize camera access
FILE_PATH_LOGS_FOLDER = os.path.join(os.path.dirname(__file__), '..', 'Log Files')


def setup_logger(name, log_file, level=logging.DEBUG):
    """Sets up a logger with a file handler."""
    handler = logging.FileHandler(log_file, mode='w')
    formatter = logging.Formatter('%(levelname)s: %(message)s')
    handler.setFormatter(formatter)

    return_logger = logging.getLogger(name)
    return_logger.setLevel(level)
    return_logger.addHandler(handler)
    return_logger.propagate = False

    return return_logger


logger = setup_logger('Generator', os.path.join(FILE_PATH_LOGS_FOLDER, 'Generator.log'))


class Generator:
    def __init__(self):
        self.frame = None  # Will store the captured image frame
        logger.info('Instance created')

    def take_picture(self):
        """
        Attempts to capture an image from the default camera.
        Uses a file lock to prevent concurrent access to the camera.
        :return: True if image was successfully captured, False otherwise.
        """
        ret_val = False
        logger.info('Started image capturing process')

        with FileLock(LOCK_FILE):  # Ensures only one process uses the camera at a time
            try:
                camera = cv2.VideoCapture(0, cv2.CAP_DSHOW)

                if not camera.isOpened():
                    logger.error('Camera not available')
                else:
                    ret, frame = camera.read()  # Attempt to capture a frame

                    if ret:
                        logger.debug("Captured image successfully!")
                        self.frame = frame
                        ret_val = True
                    else:
                        logger.error("Error: No image found")

            except Exception as e:
                logger.exception(f"Exception while capturing image: {e}")

            finally:
                camera.release()  # Always release the camera

        return ret_val

    def extract_data(self, length):
        """
        Converts the captured image into a bitstring using grayscale and red channel LSBs.
        Adds entropy by XORing the two bitstreams.
        :param length: The desired bit length of the output
        :return: A binary string of the requested length
        """
        size = math.ceil(math.sqrt(length))  # Ensure image contains enough pixels
        if not self.take_picture():
            raise RuntimeError("Failed to capture image for randomness")

        try:
            # Convert image to grayscale
            frame_gray = cv2.cvtColor(self.frame, cv2.COLOR_BGR2GRAY)
            frame_gray = cv2.resize(frame_gray, (size, size))

            # Extract red channel for additional entropy
            frame_red = self.frame[:, :, 2]
            frame_red = cv2.resize(frame_red, (size, size))

            # Flatten both channels to a list of pixel values
            pixel_values_gray = frame_gray.flatten().tolist()
            pixel_values_red = frame_red.flatten().tolist()

            # Extract LSBs from both channels
            bit_list_gray = [x % 2 for x in pixel_values_gray[:length * 2]]
            bit_list_red = [x % 2 for x in pixel_values_red[:length * 2]]

            # XOR the two bitstreams to enhance randomness
            mixed_bits = [bit_list_gray[i] ^ bit_list_red[i] for i in range(len(bit_list_gray))]

            return "".join(map(str, mixed_bits[:length]))

        except Exception as e:
            logger.exception(f"Failed during data extraction: {e}")
            raise

    @staticmethod
    def is_prime(n, k=5):
        """
        Miller-Rabin probabilistic primality test.
        :param n: Integer to test for primality
        :param k: Number of test rounds (higher = more accuracy)
        :return: True if n is probably prime, False otherwise
        """
        if n <= 1:
            return False
        if n <= 3:
            return True
        if n % 2 == 0:
            return False

        # Write n-1 as 2^r * d
        r, d = 0, n - 1
        while d % 2 == 0:
            r += 1
            d //= 2

        for _ in range(k):
            a = random.randint(2, n - 2)
            x = pow(a, d, n)

            if x in (1, n - 1):
                continue

            for _ in range(r - 1):
                x = pow(x, 2, n)
                if x == n - 1:
                    break
            else:
                return False  # Definitely composite

        return True  # Probably prime

    def generate_int(self, length):
        """
        Uses entropy from camera to generate a random integer, then hashes it.
        :param length: Desired bit length of the output
        :return: A secure random integer of approximately the given bit length
        """
        try:
            # Get random bits from image entropy
            raw_bits = self.extract_data(length)

            # Hash for uniformity and cryptographic strength
            hashed_bits = hashlib.blake2b(raw_bits.encode(), digest_size=length // 8).hexdigest()

            result = int(hashed_bits, 16)
            logger.debug(f"Extracted number: {result}")
            return result

        except Exception as e:
            logger.exception(f"Failed to generate integer: {e}")
            raise

    def generate_prime(self, bit_length):
        """
        Generates a random prime number using camera entropy and Miller-Rabin test.
        :param bit_length: Desired bit length of the output prime
        :return: A large prime number
        """
        try:
            num = self.generate_int(bit_length) | 1  # Make sure it's odd

            # Increment until a prime is found
            while not self.is_prime(num):
                num += 2

            assert isinstance(num, int), "Output is not an integer"
            assert self.is_prime(num), "Generated number is not prime"

            logger.debug(f"Generated prime number: {num}")
            return num

        except Exception as e:
            logger.exception(f"Failed to generate prime: {e}")
            raise


if __name__ == '__main__':
    gen = Generator()

    # Generate a 128-bit prime number from image-based entropy
    prime = gen.generate_prime(128)

    # Assertions to verify correctness
    assert isinstance(prime, int), "Output is not an integer"
    assert gen.is_prime(prime), "Generated number is not prime"
    assert prime.bit_length() >= 128, "Prime number is too small"

    print("Prime check:", gen.is_prime(prime))
    print("Prime number:", prime)
    print("Hex:", hex(prime))
    print("Hex length:", len(hex(prime)) - 2)
