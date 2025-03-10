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


if __name__ == '__main__':
    gen = Generator()
    print(gen.take_picture())
