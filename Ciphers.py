import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding


class Symetric:

    def encrypt(self, algorithm, password, file):
        backend = default_backend()
        salt = os.urandom(16)

        # AES128
        if algorithm == 1:
            # do stuff
            return

        # 3DES
        elif algorithm == 2:
            return

        # CHACHA20
        elif algorithm == 3:
            return

        return

    def decrypt(self, algorithm, password, file):
        backend = default_backend()

        # AES128
        if algorithm == 1:
            # do stuff
            return

        # 3DES
        elif algorithm == 2:
            return

        # CHACHA20
        elif algorithm == 3:
            return

        return


class Assymetric:

    def gen_key_pair(self):
        return

    def save_priv_key(self):
        return

    def save_pub_key(self):
        return

    def load_priv_key(self):
        return

    def load_pub_key(self):
        return

    def encrypt(self):
        return

    def decrypt(self):
        return
