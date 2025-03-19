"""
Author: Tomer Meskin
Date: 08/03/2025

Description: The Generator used for creating truly random numbers using
a picture captured by the camera, used for encryption
"""

import logging
import cv2
import time
import math
from filelock import FileLock

LOCK_FILE = 'camera.lock'  # Lock file to serialize camera access


class Generator:
    def __init__(self):
        self.frame = None

    def take_picture(self):
        """
        Tries to open the camera, capture an image, and release it.
        Uses FileLock for camera resource.
        """
        ret_val = False

        with FileLock(LOCK_FILE):  # Ensures only one process can access the camera at a time
            camera = cv2.VideoCapture(0)

            if not camera.isOpened():
                print(f"Camera not available")
                camera.release()
            else:
                ret, frame = camera.read()  # Only read once

                if ret:
                    print(f"Captured image successfully!")
                    cv2.imshow("Captured Image", frame)
                    cv2.waitKey(1000)  # Show for 1 second
                    cv2.destroyAllWindows()
                    camera.release()
                    self.frame = frame
                    ret_val = True
                else:
                    print(f"Error: No image found")

                camera.release()

        return ret_val

    def extract_data(self, length):
        size = math.ceil(math.sqrt(length))   # calculate length of side of square for picture
        self.take_picture()

        frame = cv2.cvtColor(self.frame, cv2.COLOR_BGR2GRAY)   # processes frame to grayscale
        frame = cv2.resize(frame, (size, size))

        cv2.imshow("Captured Image", frame)
        cv2.waitKey(5000)  # Show for 1 second
        cv2.destroyAllWindows()

        # list of every pixel's illumination value
        lumval_list = []
        for val in frame.tolist():
            lumval_list.extend(val)

        return "".join([str(x % 2) for x in lumval_list[:length]])

    def generate_int(self, length):
        return int("0b" + self.extract_data(length), 2)


if __name__ == '__main__':
    gen = Generator()
    print(gen.extract_data(128))
