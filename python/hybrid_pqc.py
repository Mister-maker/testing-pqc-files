# Quantum Safe - Hybrid PQC Implementations
import oqs
import os
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from pqcrypto.kem.kyber768 import generate_keypair, encrypt, decrypt


# Hybrid X25519 + Kyber768
def hybrid_x25519_kyber768():
    """Hybrid X25519 + Kyber768 key exchange"""
    # Classical X25519
    x25519_private = X25519PrivateKey.generate()
    x25519_public = x25519_private.public_key()

    # Post-quantum Kyber768
    kyber_pk, kyber_sk = generate_keypair()
    kyber_ct, kyber_ss = encrypt(kyber_pk)

    # Combine shared secrets with HKDF
    combined = x25519_public.public_bytes_raw() + kyber_ss
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"hybrid-kem",
        backend=default_backend()
    )
    final_key = hkdf.derive(combined)
    return final_key, kyber_ct


def hybrid_ecdh_mlkem():
    """ECDH + ML-KEM hybrid"""
    from cryptography.hazmat.primitives.asymmetric import ec

    # ECDH
    ec_private = ec.generate_private_key(ec.SECP256R1())
    ec_public = ec_private.public_key()

    # ML-KEM (Kyber768)
    with oqs.KeyEncapsulation("Kyber768") as kem:
        mlkem_pk = kem.generate_keypair()
        mlkem_ct, mlkem_ss = kem.encap_secret(mlkem_pk)

    return mlkem_ss, mlkem_ct


def hybrid_tls_pqc():
    """Hybrid TLS with PQC - X25519Kyber768Draft00"""
    # X25519 component
    x25519_private = X25519PrivateKey.generate()
    x25519_public = x25519_private.public_key()

    # Kyber768 component
    with oqs.KeyEncapsulation("Kyber768") as kem:
        kyber_pk = kem.generate_keypair()
        return x25519_public, kyber_pk


def x25519_kyber768_draft00():
    """IETF draft hybrid key exchange"""
    # X25519
    x25519_private = X25519PrivateKey.generate()
    x25519_public = x25519_private.public_key()

    # Kyber768
    kyber_pk, kyber_sk = generate_keypair()

    hybrid_public = x25519_public.public_bytes_raw() + kyber_pk
    return hybrid_public


def ecdh_kyber_composite():
    """Composite key encapsulation"""
    from cryptography.hazmat.primitives.asymmetric import ec

    # ECDH P-384
    ec_private = ec.generate_private_key(ec.SECP384R1())
    ec_public = ec_private.public_key()

    # Kyber768
    with oqs.KeyEncapsulation("Kyber768") as kem:
        kyber_pk = kem.generate_keypair()
        kyber_ct, kyber_ss = kem.encap_secret(kyber_pk)

    # Combine with HKDF
    combined = ec_public.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    ) + kyber_ss

    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"composite-kem",
        backend=default_backend()
    )
    composite_secret = hkdf.derive(combined)
    return composite_secret, kyber_ct


# Import for composite function
from cryptography.hazmat.primitives import serialization
