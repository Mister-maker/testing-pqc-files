# Quantum Safe - Digital Signatures
import oqs
from pqcrypto.sign.dilithium2 import generate_keypair, sign, verify
from pqcrypto.sign.dilithium3 import generate_keypair as dilithium3_keypair
from pqcrypto.sign.dilithium5 import generate_keypair as dilithium5_keypair
from pqcrypto.sign.falcon512 import generate_keypair as falcon512_keypair
from pqcrypto.sign.sphincs_shake256_128f_robust import generate_keypair as sphincs_keypair


def ml_dsa_44_signature():
    """ML-DSA-44 (Dilithium2) digital signature"""
    public_key, secret_key = generate_keypair()
    message = b"quantum safe message"
    signature = sign(secret_key, message)
    verified = verify(public_key, message, signature)
    return verified


def ml_dsa_65_example():
    """ML-DSA-65 (Dilithium3) digital signature"""
    public_key, secret_key = dilithium3_keypair()
    signature = sign(secret_key, b"test data")
    return signature


def ml_dsa_87_signature():
    """ML-DSA-87 (Dilithium5) digital signature"""
    public_key, secret_key = dilithium5_keypair()
    signature = sign(secret_key, b"ml-dsa-87")
    return signature


def falcon_512_signature():
    """Falcon-512 digital signature"""
    public_key, secret_key = falcon512_keypair()
    msg = b"falcon signed message"
    signature = sign(secret_key, msg)
    valid = verify(public_key, msg, signature)
    return valid


def slh_dsa_sphincs_plus():
    """SLH-DSA (SPHINCS+) digital signature"""
    public_key, secret_key = sphincs_keypair()
    signature = sign(secret_key, b"data")
    return signature


def oqs_dilithium_signature():
    """liboqs Dilithium2 implementation"""
    with oqs.Signature("Dilithium2") as signer:
        public_key = signer.generate_keypair()
        message = b"oqs dilithium message"
        signature = signer.sign(message)
        is_valid = signer.verify(message, signature, public_key)
        return is_valid


def xmss_signature_example():
    """XMSS hash-based signature"""
    with oqs.Signature("Dilithium2") as signer:
        public_key = signer.generate_keypair()
        signature = signer.sign(b"xmss message")
        return public_key, signature


def lms_hash_based_signature():
    """LMS - Leighton-Micali Signature"""
    with oqs.Signature("Dilithium3") as signer:
        keypair = signer.generate_keypair()
        return keypair
