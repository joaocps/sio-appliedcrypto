import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


# TODO mudar ctr
class Symmetric:

    def encrypt(self, algorithm, password, msg, filename, hasht, block):
        backend = default_backend()
        salt = os.urandom(16)

        crypto_file = filename + "_stuff"

        fout = open(crypto_file, "wb")
        fout.write(salt)

        if hasht == 1:
            alg = hashes.SHA256()
        elif hasht == 2:
            alg = hashes.SHA512()
        else:
            return None

        # AES128
        if algorithm == 1:
            iv = os.urandom(16)

            fout.write(iv)
            fout.write(password.encode())
            fout.close()

            if block == 1:
                m = modes.CBC(iv)
            elif block == 2:
                m = modes.CTR(iv)
            else:
                return None

            kdf = PBKDF2HMAC(algorithm=alg, length=32, salt=salt, iterations=100000, backend=backend)
            key = kdf.derive(password.encode())

            cipher = Cipher(algorithms.AES(key), mode=m, backend=backend)

            encryptor = cipher.encryptor()

            padder = padding.PKCS7(128).padder()
            fbytes = msg.encode()
            padded_data = padder.update(fbytes)
            padded_data += padder.finalize()

            ct = encryptor.update(padded_data)
            return ct
        # 3DES
        elif algorithm == 2:

            iv = os.urandom(8)

            fout.write(iv)
            fout.write(password.encode())
            fout.close()

            if block == 1:
                m = modes.CBC(iv)
            elif block == 2:
                m = modes.CTR(iv)
            else:
                return None

            kdf = PBKDF2HMAC(algorithm=alg, length=16, salt=salt, iterations=100000, backend=backend)
            key = kdf.derive(password.encode())

            cipher = Cipher(algorithms.TripleDES(key), mode=m, backend=backend)

            encryptor = cipher.encryptor()

            padder = padding.PKCS7(8).padder()
            fbytes = msg.encode()
            padded_data = padder.update(fbytes)
            padded_data += padder.finalize()

            ct = encryptor.update(padded_data)
            return ct

        # CHACHA20
        elif algorithm == 3:

            nonce = os.urandom(16)

            fout.write(nonce)
            fout.write(password.encode())
            fout.close()

            kdf = PBKDF2HMAC(algorithm=alg, length=32, salt=salt, iterations=100000, backend=backend)
            key = kdf.derive(password.encode())

            cipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None, backend=backend)
            encryptor = cipher.encryptor()

            return encryptor.update(msg.encode())

        return None

    def decrypt(self, algorithm, msg, file, hasht, block):
        backend = default_backend()

        if hasht == 1:
            alg = hashes.SHA256()
        elif hasht == 2:
            alg = hashes.SHA512()
        else:
            return None

        # AES128
        if algorithm == 1:
            f = open(file, "rb")
            try:
                salt = f.read(16)
                iv = f.read(16)
                password = f.read()
            finally:
                f.close()

            if block == 1:
                m = modes.CBC(iv)
            elif block == 2:
                m = modes.CTR(iv)
            else:
                return None

            kdf = PBKDF2HMAC(algorithm=alg, length=32, salt=salt, iterations=100000, backend=backend)
            key = kdf.derive(password)

            decipher = Cipher(algorithms.AES(key), mode=m, backend=default_backend())
            decryptor = decipher.decryptor()
            dec = decryptor.update(msg)

            return dec.decode()

        # 3DES
        elif algorithm == 2:
            f = open(file, "rb")
            try:
                salt = f.read(16)
                iv = f.read(8)
                password = f.read()
            finally:
                f.close()

            if block == 1:
                m = modes.CBC(iv)
            elif block == 2:
                m = modes.CTR(iv)
            else:
                return None

            kdf = PBKDF2HMAC(algorithm=alg, length=16, salt=salt, iterations=100000, backend=backend)
            key = kdf.derive(password)

            decipher = Cipher(algorithms.TripleDES(key), mode=m, backend=default_backend())
            decryptor = decipher.decryptor()
            dec = decryptor.update(msg)

            return dec.decode()

        # CHACHA20
        elif algorithm == 3:
            f = open(file, "rb")
            try:
                salt = f.read(16)
                nonce = f.read(16)
                password = f.read()
            finally:
                f.close()

            kdf = PBKDF2HMAC(algorithm=alg, length=32, salt=salt, iterations=100000, backend=backend)
            key = kdf.derive(password)

            decipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None, backend=default_backend())
            decryptor = decipher.decryptor()
            dec = decryptor.update(msg)

            return dec.decode()

        return None


class DHexchange:
    def create_secret(self, private, public):
        # TODO adicionar load public/private pem ou ler no client/server
        return private.exchange(public)

    def derive_key(self, shared_secret):
        return HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'handshake data',
            backend=default_backend()
        ).derive(shared_secret)


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
