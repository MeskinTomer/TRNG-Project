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

log_file = os.path.join(FILE_PATH_LOGS_FOLDER, 'Generator.log')
logging.basicConfig(
    filename=log_file,
    level=logging.DEBUG,
    filemode="w",
    format="%(levelname)s: %(message)s"
)


class Generator:
    def __init__(self):
        self.frame = None

    def take_picture(self):
        """
        Tries to open the camera, capture an image, and release it.
        Uses FileLock for camera resource.
        :return: True/False depending on success of capturing.
        """
        ret_val = False

        with FileLock(LOCK_FILE):  # Ensures only one process can access the camera at a time
            camera = cv2.VideoCapture(0)

            if not camera.isOpened():
                logging.error('Camera not available')
                camera.release()
            else:
                ret, frame = camera.read()  # Only read once

                if ret:
                    logging.info("Captured image successfully!")
                    cv2.imshow("Captured Image", frame)
                    cv2.waitKey(1000)  # Show for 1 second
                    cv2.destroyAllWindows()
                    camera.release()
                    self.frame = frame
                    ret_val = True
                else:
                    logging.error("Error: No image found")

                camera.release()

        return ret_val

    def extract_data(self, length):
        """
        Turns the frame into grayscale, extracts illumination values of pixels
        and mashes them into a byte list
        :param length: The desired bit length of the bit-list
        :return: The bit-list
        """
        size = math.ceil(math.sqrt(length))   # calculate length of side of square for picture
        self.take_picture()

        frame_gray = cv2.cvtColor(self.frame, cv2.COLOR_BGR2GRAY)   # processes frame to grayscale
        frame_gray = cv2.resize(frame_gray, (size, size))

        frame_red = self.frame[:, :, 2]  # Extract red channel for extra entropy
        frame_red = cv2.resize(frame_red, (size, size))

        # Extract least significant bits (LSB) from grayscale and red channel
        pixel_values_gray = frame_gray.flatten().tolist()
        pixel_values_red = frame_red.flatten().tolist()

        bit_list_gray = [x % 2 for x in pixel_values_gray[:length * 2]]
        bit_list_red = [x % 2 for x in pixel_values_red[:length * 2]]

        # XOR the two bit streams for additional randomness
        mixed_bits = [bit_list_gray[i] ^ bit_list_red[i] for i in range(len(bit_list_gray))]

        return "".join(map(str, mixed_bits[:length]))

    @staticmethod
    def is_prime(n, k=5):
        """
        Miller-Rabin primality test.
        :param n: The number to check for primality.
        :param k: Number of iterations for accuracy.
        :return: True if prime, False otherwise.
        """
        if n <= 1:
            return False
        if n <= 3:
            return True
        if n % 2 == 0:
            return False

        r, d = 0, n - 1
        while d % 2 == 0:
            r += 1
            d //= 2

        for _ in range(k):
            a = random.randint(2, n - 2)
            x = pow(a, d, n)
            if x == 1 or x == n - 1:
                continue
            for _ in range(r - 1):
                x = pow(x, 2, n)
                if x == n - 1:
                    break
            else:
                return False
        return True

    def generate_int(self, length):
        """
        Turns the processed bit-string into an integer, applying hashing for extra security.
        :param length: The desired bit length of the integer
        :return: The final random integer
        """
        raw_bits = self.extract_data(length)
        hashed_bits = hashlib.blake2b(raw_bits.encode(), digest_size=length // 8).hexdigest()
        logging.info(f"Extracted number: {int(hashed_bits, 16)}")

        return int(hashed_bits, 16)

    def generate_prime(self, bit_length):
        """
        Generates a prime number of the given bit length.
        :param bit_length: The desired bit length of the prime.
        :return: A prime number.
        """
        num = self.generate_int(bit_length) | 1

        if num % 2 == 0:
            num += 1

        while not self.is_prime(num):
            num += 2

        logging.info(f"Generated prime number: {num}")
        return num


if __name__ == '__main__':
    gen = Generator()
    num = gen.generate_prime(128)
    print(gen.is_prime(num))
    print(num)
    print(hex(num))
    print(len(hex(num)) - 2)
