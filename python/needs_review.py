# Needs Review - Generic Terms, Ambiguous AES, Library References
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
import os


# Generic Terms (Need context to determine security)
def encrypt(data: bytes, key: bytes) -> bytes:
    """Generic encrypt function"""
    cipher = create_cipher(key)
    encryptor = cipher.encryptor()
    return encryptor.update(data) + encryptor.finalize()


def decrypt(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    """Generic decrypt function"""
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()


def sign(message: bytes, private_key) -> bytes:
    """Generic sign function"""
    from cryptography.hazmat.primitives.asymmetric import padding
    signature = private_key.sign(
        message,
        padding.PKCS1v15(),
        hashes.SHA256()
    )
    return signature


def verify(message: bytes, signature: bytes, public_key) -> bool:
    """Generic verify function"""
    from cryptography.hazmat.primitives.asymmetric import padding
    try:
        public_key.verify(signature, message, padding.PKCS1v15(), hashes.SHA256())
        return True
    except:
        return False


def hash(data: bytes) -> bytes:
    """Generic hash - could be any algorithm"""
    return hashlib.sha256(data).digest()


def generate_key(length: int = 32) -> bytes:
    """Generic key generation"""
    return os.urandom(length)


def create_cipher(key: bytes):
    """Create cipher instance"""
    iv = os.urandom(16)
    return Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())


# Ambiguous AES (key size not specified)
def aes_encrypt(plaintext: bytes, key: bytes) -> bytes:
    """AES without explicit key size - could be 128, 192, or 256"""
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    return encryptor.update(plaintext) + encryptor.finalize()


def aes_decrypt(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    """AES decryption"""
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()


def aes_cbc_mode(data: bytes, key: bytes, iv: bytes) -> bytes:
    """AES CBC mode"""
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    return encryptor.update(data) + encryptor.finalize()


def aes_ecb_mode(data: bytes, key: bytes) -> bytes:
    """AES ECB mode - INSECURE, do not use"""
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()
    return encryptor.update(data) + encryptor.finalize()


# Library References
def use_cryptography():
    """Using cryptography library"""
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    key = Fernet.generate_key()
    f = Fernet(key)
    return f


def use_pycryptodome():
    """Using PyCryptodome library"""
    from Crypto.Cipher import AES
    from Crypto.Random import get_random_bytes
    key = get_random_bytes(32)
    cipher = AES.new(key, AES.MODE_GCM)
    return cipher


def use_nacl():
    """Using PyNaCl (libsodium) library"""
    import nacl.secret
    import nacl.utils
    key = nacl.utils.random(nacl.secret.SecretBox.KEY_SIZE)
    box = nacl.secret.SecretBox(key)
    return box


def use_openssl():
    """OpenSSL bindings via pyOpenSSL"""
    from OpenSSL import crypto
    key = crypto.PKey()
    key.generate_key(crypto.TYPE_RSA, 2048)
    return key
