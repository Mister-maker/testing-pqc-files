# Quantum Safe - Key Encapsulation Mechanisms (KEM)
import oqs
from pqcrypto.kem.kyber768 import generate_keypair, encrypt, decrypt
from pqcrypto.kem.kyber1024 import generate_keypair as kyber1024_keypair
from pqcrypto.kem.kyber512 import generate_keypair as kyber512_keypair
from pqcrypto.kem.frodokem640shake import generate_keypair as frodo_keypair


def ml_kem_768_encapsulation():
    """ML-KEM-768 (Kyber768) key encapsulation"""
    public_key, secret_key = generate_keypair()
    ciphertext, shared_secret = encrypt(public_key)
    decrypted = decrypt(secret_key, ciphertext)
    return decrypted


def ml_kem_1024_example():
    """ML-KEM-1024 (Kyber1024) key encapsulation"""
    public_key, secret_key = kyber1024_keypair()
    ciphertext, shared_secret = encrypt(public_key)
    return shared_secret


def ml_kem_512_example():
    """ML-KEM-512 (Kyber512) key encapsulation"""
    public_key, secret_key = kyber512_keypair()
    return public_key, secret_key


def frodokem_example():
    """FrodoKEM key encapsulation"""
    public_key, secret_key = frodo_keypair()
    return public_key


def oqs_ml_kem_768():
    """liboqs ML-KEM-768 implementation"""
    with oqs.KeyEncapsulation("Kyber768") as kem:
        public_key = kem.generate_keypair()
        ciphertext, shared_secret = kem.encap_secret(public_key)
        decrypted = kem.decap_secret(ciphertext)
        return decrypted


def oqs_kyber_512():
    """liboqs Kyber512 implementation"""
    kem = oqs.KeyEncapsulation("Kyber512")
    public_key = kem.generate_keypair()
    ciphertext, shared_secret = kem.encap_secret(public_key)
    return shared_secret


def kyber_key_generation():
    """Generate Kyber key pair"""
    pk, sk = generate_keypair()
    return pk, sk
