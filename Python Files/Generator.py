"""
Author: Tomer Meskin
Date: 08/03/2025

Description: The Generator used for creating truly random numbers using
a picture captured by the camera, used for encryption
"""

import logging
import cv2
import time

MAX_RETRIES = 5
RETRY_DELAY = 1


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
            camera = cv2.VideoCapture(0, cv2.CAP_DSHOW)

            if camera.isOpened():
                ret, frame = camera.read()
                if ret:
                    cv2.imshow("Captured Image", frame)
                    cv2.waitKey(1000)  # Show for 1 second
                    cv2.destroyAllWindows()
                    camera.release()
                    return
                else:
                    print("Error: No image found")
                    camera.release()
                    return

            print(f"Attempt {attempt + 1}: Camera not available, retrying...")
            camera.release()
            time.sleep(RETRY_DELAY)  # Wait before retrying

        print("Error: Could not access camera after multiple attempts.")


if __name__ == '__main__':
    gen = Generator()
    gen.take_picture()
