import os

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


class Asymmetric(object):
    """
    Class with asymmetric encryption methods
    """

    def generate_rsa_keys(self, path, client_name, password):
        """
        Create and save the rsa private and public key to file
        """
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=4096, backend=default_backend())
        pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(password.encode()))

        with open(os.path.join(path, client_name + '_private_rsa.pem'), 'wb') as file:
            file.write(pem)

        public_key = private_key.public_key()
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo)

        with open(os.path.join(path, client_name + '_public_rsa.pem'), 'wb') as file:
            file.write(public_pem)

        return private_key, public_pem

    def load_rsa_public_key(self, file):
        """
        Load RSA public key from file
        :param file:
        :return: public_key
        """

        with open(file, "rb") as pubkey_file:
            public_key = load_pem_public_key(pubkey_file.read(), backend=default_backend())
            if not isinstance(public_key, rsa.RSAPublicKey):
                print("ERROR, public key not loaded")
            else:
                return public_key

    def load_pub_from_str(self, pk):
        return serialization.load_pem_public_key(
            pk,
            backend=default_backend())


class Symmetric:

    def encrypt(self, algorithm, msg, hasht, block, key="", password="", filename=""):
        backend = default_backend()
        salt = os.urandom(16)

        # crypto_file = filename + "_stuff"
        #
        # fout = open(crypto_file, "wb")
        # fout.write(salt)

        if hasht == 1:
            alg = hashes.SHA256()
        elif hasht == 2:
            alg = hashes.SHA512()
        else:
            return None

        # AES128
        if algorithm == 1:
            iv = os.urandom(16)

            # fout.write(iv)
            # fout.write(password.encode())
            # fout.close()

            if block == 1:
                m = modes.CBC(iv)
            elif block == 2:
                m = modes.CTR(iv)
            else:
                return None
            if key == "":
                kdf = PBKDF2HMAC(algorithm=alg, length=32, salt=salt, iterations=100000, backend=backend)
                key = kdf.derive(password.encode())

            cipher = Cipher(algorithms.AES(key), mode=m, backend=backend)

            encryptor = cipher.encryptor()

            if block == 1:
                padder = padding.PKCS7(128).padder()
                padded_data = padder.update(msg)
                padded_data += padder.finalize()
                ct = encryptor.update(padded_data)
                return iv + salt + ct
            else:
                ct = encryptor.update(msg)
                return iv + salt + ct
        # 3DES
        elif algorithm == 2:

            iv = os.urandom(8)

            # fout.write(iv)
            # fout.write(password.encode())
            # fout.close()

            if block == 1:
                m = modes.CBC(iv)
            elif block == 2:
                m = modes.CTR(iv)
            else:
                return None
            if key == "":
                kdf = PBKDF2HMAC(algorithm=alg, length=16, salt=salt, iterations=100000, backend=backend)
                key = kdf.derive(password.encode())

            cipher = Cipher(algorithms.TripleDES(key), mode=m, backend=backend)

            encryptor = cipher.encryptor()

            if block == 1:
                padder = padding.PKCS7(8).padder()
                padded_data = padder.update(msg)
                padded_data += padder.finalize()
                ct = encryptor.update(padded_data)
                return iv + salt + ct
            else:
                ct = encryptor.update(msg)
                return iv + salt + ct

        # CHACHA20
        elif algorithm == 3:

            nonce = os.urandom(16)

            # fout.write(nonce)
            # fout.write(password.encode())
            # fout.close()

            if key == "":
                kdf = PBKDF2HMAC(algorithm=alg, length=32, salt=salt, iterations=100000, backend=backend)
                key = kdf.derive(password.encode())

            cipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None, backend=backend)
            encryptor = cipher.encryptor()
            ct = encryptor.update(msg)
            return nonce + salt + ct

        return None

    def decrypt(self, algorithm, msg, hasht, block, key="", password="", file=""):
        backend = default_backend()

        if hasht == 1:
            alg = hashes.SHA256()
        elif hasht == 2:
            alg = hashes.SHA512()
        else:
            return None

        # AES128
        if algorithm == 1:
            iv = msg[0:16]
            salt = msg[16:32]
            msg = msg[32:]
            # f = open(file, "rb")
            # try:
            #     salt = f.read(16)
            #     iv = f.read(16)
            #     password = f.read()
            # finally:
            #     f.close()

            if block == 1:
                m = modes.CBC(iv)
            elif block == 2:
                m = modes.CTR(iv)
            else:
                return None
            if key == "":
                kdf = PBKDF2HMAC(algorithm=alg, length=32, salt=salt, iterations=100000, backend=backend)
                key = kdf.derive(password.encode())

            decipher = Cipher(algorithms.AES(key), mode=m, backend=default_backend())
            decryptor = decipher.decryptor()
            dec = decryptor.update(msg)
            if block == 1:
                unpadder = padding.PKCS7(128).unpadder()
                data = unpadder.update(dec)
                data += unpadder.finalize()
                return data
            else:
                return dec

        # 3DES
        elif algorithm == 2:
            iv = msg[0:8]
            salt = msg[8:24]
            msg = msg[24:]
            # f = open(file, "rb")
            # try:
            #     salt = f.read(16)
            #     iv = f.read(8)
            #     password = f.read()
            # finally:
            #     f.close()

            if block == 1:
                m = modes.CBC(iv)
            elif block == 2:
                m = modes.CTR(iv)
            else:
                return None
            if key == "":
                kdf = PBKDF2HMAC(algorithm=alg, length=16, salt=salt, iterations=100000, backend=backend)
                key = kdf.derive(password.encode())

            decipher = Cipher(algorithms.TripleDES(key), mode=m, backend=default_backend())
            decryptor = decipher.decryptor()
            dec = decryptor.update(msg)
            if block == 1:
                unpadder = padding.PKCS7(8).unpadder()
                data = unpadder.update(dec)
                data += unpadder.finalize()
                return data
            else:
                return dec

        # CHACHA20
        elif algorithm == 3:
            iv = msg[0:16]
            salt = msg[16:32]
            msg = msg[32:]
            # f = open(file, "rb")
            # try:
            #     salt = f.read(16)
            #     nonce = f.read(16)
            #     password = f.read()
            # finally:
            #     f.close()
            nonce = iv
            if key == "":
                kdf = PBKDF2HMAC(algorithm=alg, length=32, salt=salt, iterations=100000, backend=backend)
                key = kdf.derive(password.encode())

            decipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None, backend=default_backend())
            decryptor = decipher.decryptor()
            dec = decryptor.update(msg)

            return dec

        return None

    def handshake_encrypt(self, message, key=""):
        backend = default_backend()
        iv = os.urandom(16)
        salt = os.urandom(16)
        if key == "":
            kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000, backend=backend)
            key = kdf.derive(b'hs')

        cipher = Cipher(algorithms.AES(key), mode=modes.CBC(iv), backend=backend)
        encryptor = cipher.encryptor()

        padder = padding.PKCS7(128).padder()

        padded_data = padder.update(message)
        padded_data += padder.finalize()

        ct = encryptor.update(padded_data)
        return iv + salt + ct

    def handshake_decrypt(self, message, key=""):
        backend = default_backend()
        iv = message[0:16]
        salt = message[16:32]
        message = message[32:]

        if key == "":
            kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000, backend=backend)
            key = kdf.derive(b'hs')

        decipher = Cipher(algorithms.AES(key), mode=modes.CBC(iv), backend=default_backend())
        decryptor = decipher.decryptor()
        dec = decryptor.update(message)
        unpadder = padding.PKCS7(128).unpadder()
        data = unpadder.update(dec)
        data += unpadder.finalize()
        return data


class DHexchange:

    def generate_keys(self):
        private = ec.generate_private_key(
            ec.SECP384R1(), default_backend()
        )
        public = private.public_key()
        public_pem = public.public_bytes(encoding=serialization.Encoding.PEM,
                                         format=serialization.PublicFormat.SubjectPublicKeyInfo)

        return private, public_pem

    def create_secret(self, private, public):
        return private.exchange(ec.ECDH(), public)

    def derive_key(self, shared_secret, hasht):
        if hasht == 1:
            alg = hashes.SHA256()
        elif hasht == 2:
            alg = hashes.SHA512()
        else:
            return None
        key = HKDF(
            algorithm=alg,
            length=32,
            salt=None,
            info=b'handshake data',
            backend=default_backend()
        ).derive(shared_secret)

        return key
