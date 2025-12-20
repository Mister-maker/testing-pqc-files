# Quantum Vulnerable - Broken/Weak Algorithms (DO NOT USE IN PRODUCTION)
import hashlib
import hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa, dsa, ec, dh
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from Crypto.Cipher import DES, DES3, Blowfish, ARC4, IDEA


# Broken Hash (VULNERABLE)
def md5_broken_hash(data: bytes) -> bytes:
    """MD5 hash - BROKEN, do not use"""
    return hashlib.md5(data).digest()


def md4_broken_hash(data: bytes) -> bytes:
    """MD4 hash - BROKEN, do not use"""
    from Crypto.Hash import MD4
    h = MD4.new()
    h.update(data)
    return h.digest()


def sha1_broken_hash(data: bytes) -> bytes:
    """SHA-1 hash - BROKEN, do not use"""
    return hashlib.sha1(data).digest()


def ripemd_weak_hash(data: bytes) -> bytes:
    """RIPEMD-160 hash - weak"""
    from Crypto.Hash import RIPEMD160
    h = RIPEMD160.new()
    h.update(data)
    return h.digest()


# Weak Symmetric (VULNERABLE)
def des_weak_cipher(plaintext: bytes, key: bytes) -> bytes:
    """DES cipher - WEAK, do not use"""
    cipher = DES.new(key[:8], DES.MODE_ECB)
    return cipher.encrypt(plaintext)


def triple_des_3des_cipher(plaintext: bytes, key: bytes) -> bytes:
    """3DES cipher - legacy, avoid if possible"""
    cipher = DES3.new(key[:24], DES3.MODE_CBC, iv=b'\x00' * 8)
    return cipher.encrypt(plaintext)


def rc4_stream_cipher(plaintext: bytes, key: bytes) -> bytes:
    """RC4 stream cipher - BROKEN, do not use"""
    cipher = ARC4.new(key)
    return cipher.encrypt(plaintext)


def blowfish_cipher(plaintext: bytes, key: bytes) -> bytes:
    """Blowfish cipher - legacy"""
    cipher = Blowfish.new(key, Blowfish.MODE_CBC, iv=b'\x00' * 8)
    return cipher.encrypt(plaintext)


def idea_cipher(plaintext: bytes, key: bytes) -> bytes:
    """IDEA cipher - legacy"""
    cipher = IDEA.new(key[:16], IDEA.MODE_CBC, iv=b'\x00' * 8)
    return cipher.encrypt(plaintext)


# Weak MAC (VULNERABLE)
def hmac_md5_weak(key: bytes, message: bytes) -> bytes:
    """HMAC-MD5 - weak, avoid"""
    return hmac.new(key, message, hashlib.md5).digest()


def hmac_sha1_weak(key: bytes, message: bytes) -> bytes:
    """HMAC-SHA1 - weak, avoid"""
    return hmac.new(key, message, hashlib.sha1).digest()


# Shor Vulnerable - Asymmetric (VULNERABLE to quantum computers)
def rsa_encryption():
    """RSA encryption - vulnerable to Shor's algorithm"""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    ciphertext = public_key.encrypt(
        b"data",
        padding.PKCS1v15()
    )
    return ciphertext


def dsa_signature():
    """DSA signature - vulnerable to Shor's algorithm"""
    private_key = dsa.generate_private_key(
        key_size=2048,
        backend=default_backend()
    )
    signature = private_key.sign(b"message", hashes.SHA256())
    return signature


def ecdsa_signature():
    """ECDSA signature - vulnerable to Shor's algorithm"""
    private_key = ec.generate_private_key(
        ec.SECP256R1(),
        backend=default_backend()
    )
    signature = private_key.sign(b"message", ec.ECDSA(hashes.SHA256()))
    return signature


def diffie_hellman_key_exchange():
    """Diffie-Hellman key exchange - vulnerable to Shor's algorithm"""
    parameters = dh.generate_parameters(generator=2, key_size=2048)
    private_key = parameters.generate_private_key()
    public_key = private_key.public_key()
    return public_key


def ecdh_key_exchange():
    """ECDH key exchange - vulnerable to Shor's algorithm"""
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()
    return public_key


# Vulnerable Curves
def secp256k1_curve():
    """secp256k1 curve - vulnerable to Shor's algorithm"""
    private_key = ec.generate_private_key(ec.SECP256K1())
    return private_key


def p384_curve():
    """P-384 curve - vulnerable to Shor's algorithm"""
    private_key = ec.generate_private_key(ec.SECP384R1())
    return private_key


def p521_curve():
    """P-521 curve - vulnerable to Shor's algorithm"""
    private_key = ec.generate_private_key(ec.SECP521R1())
    return private_key


def ed25519_signature():
    """Ed25519 signature - vulnerable to Shor's algorithm"""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    private_key = Ed25519PrivateKey.generate()
    signature = private_key.sign(b"message")
    return signature


def curve25519_key():
    """Curve25519 key - vulnerable to Shor's algorithm"""
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    private_key = X25519PrivateKey.generate()
    public_key = private_key.public_key()
    return public_key
