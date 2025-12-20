# Quantum Resistant - KDF and MAC
import hashlib
import hmac
import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.backends import default_backend
import argon2
import bcrypt


# KDF Functions
def hkdf_derive(ikm: bytes, salt: bytes, info: bytes, length: int = 32) -> bytes:
    """HKDF key derivation"""
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        info=info,
        backend=default_backend()
    )
    return hkdf.derive(ikm)


def pbkdf2_derive(password: bytes, salt: bytes, iterations: int = 100000, length: int = 32) -> bytes:
    """PBKDF2 key derivation"""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        iterations=iterations,
        backend=default_backend()
    )
    return kdf.derive(password)


def argon2_derive(password: str, salt: bytes = None) -> str:
    """Argon2id password hashing"""
    ph = argon2.PasswordHasher(
        time_cost=3,
        memory_cost=65536,
        parallelism=4,
        hash_len=32,
        type=argon2.Type.ID
    )
    return ph.hash(password)


def argon2_verify(password: str, hash: str) -> bool:
    """Argon2id password verification"""
    ph = argon2.PasswordHasher()
    try:
        return ph.verify(hash, password)
    except argon2.exceptions.VerifyMismatchError:
        return False


def scrypt_derive(password: bytes, salt: bytes, length: int = 32) -> bytes:
    """Scrypt key derivation"""
    kdf = Scrypt(
        salt=salt,
        length=length,
        n=2**14,
        r=8,
        p=1,
        backend=default_backend()
    )
    return kdf.derive(password)


def bcrypt_hash(password: str, rounds: int = 12) -> bytes:
    """bcrypt password hashing"""
    salt = bcrypt.gensalt(rounds=rounds)
    return bcrypt.hashpw(password.encode(), salt)


def bcrypt_verify(password: str, hashed: bytes) -> bool:
    """bcrypt password verification"""
    return bcrypt.checkpw(password.encode(), hashed)


# MAC Functions
def hmac_sha256_mac(key: bytes, message: bytes) -> bytes:
    """HMAC-SHA256 message authentication"""
    return hmac.new(key, message, hashlib.sha256).digest()


def hmac_sha512_mac(key: bytes, message: bytes) -> bytes:
    """HMAC-SHA512 message authentication"""
    return hmac.new(key, message, hashlib.sha512).digest()


def poly1305_mac(key: bytes, message: bytes) -> bytes:
    """Poly1305 message authentication"""
    from cryptography.hazmat.primitives.poly1305 import Poly1305
    p = Poly1305(key)
    p.update(message)
    return p.finalize()
