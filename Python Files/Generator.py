"""
Author: Tomer Meskin
Date: 08/03/2025

Description: The Generator used for creating truly random numbers using
a picture captured by the camera, used for encryption
"""

import logging
import cv2
import time
from filelock import FileLock

MAX_RETRIES = 5
RETRY_DELAY = 3
LOCK_FILE = 'camera.lock'  # Lock file to serialize camera access


class Generator:
    def __init__(self):
        pass

    @staticmethod
    def take_picture():
        """
        Tries to open the camera, capture an image, and release it.
        Retries if the camera is in use.
        """
        for attempt in range(MAX_RETRIES):
            with FileLock(LOCK_FILE):  # Ensures only one process can access the camera at a time
                camera = cv2.VideoCapture(0)

                if not camera.isOpened():
                    print(f"Attempt {attempt + 1}: Camera not available, retrying...")
                    camera.release()
                    time.sleep(RETRY_DELAY)
                    continue  # Try again

                ret, frame = camera.read()  # Only read once

                if ret:
                    print(f"Captured image successfully!")
                    cv2.imshow("Captured Image", frame)
                    cv2.waitKey(1000)  # Show for 1 second
                    cv2.destroyAllWindows()
                    camera.release()
                    return

                print(f"Error: No image found")
                camera.release()
                time.sleep(RETRY_DELAY)

        print(f"Error: Could not access camera after {MAX_RETRIES} attempts.")


if __name__ == '__main__':
    gen = Generator()
    gen.take_picture()
