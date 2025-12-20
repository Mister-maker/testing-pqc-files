# Quantum Resistant - PQC Candidates (KEM and Signatures)
import oqs


# PQC Candidate KEMs
def ntru_kem_example():
    """NTRU key encapsulation"""
    with oqs.KeyEncapsulation("NTRU-HPS-2048-509") as kem:
        public_key = kem.generate_keypair()
        ciphertext, shared_secret = kem.encap_secret(public_key)
        decrypted = kem.decap_secret(ciphertext)
        return decrypted


def classic_mceliece_kem():
    """Classic McEliece key encapsulation"""
    with oqs.KeyEncapsulation("Classic-McEliece-348864") as kem:
        public_key = kem.generate_keypair()
        ciphertext, shared_secret = kem.encap_secret(public_key)
        return shared_secret


def hqc_kem_example():
    """HQC key encapsulation"""
    with oqs.KeyEncapsulation("HQC-128") as kem:
        public_key = kem.generate_keypair()
        ciphertext, shared_secret = kem.encap_secret(public_key)
        return shared_secret


def bike_kem_example():
    """BIKE key encapsulation"""
    with oqs.KeyEncapsulation("BIKE-L1") as kem:
        public_key = kem.generate_keypair()
        ciphertext, shared_secret = kem.encap_secret(public_key)
        return shared_secret


def sike_vulnerable_kem():
    """SIKE - Supersingular Isogeny Key Encapsulation (VULNERABLE - broken)"""
    # SIKE has been broken and should not be used
    with oqs.KeyEncapsulation("SIKE-p434") as kem:
        public_key = kem.generate_keypair()
        return public_key


# PQC Candidate Signatures
def picnic_signature():
    """Picnic signature scheme"""
    with oqs.Signature("Picnic-L1-full") as signer:
        public_key = signer.generate_keypair()
        signature = signer.sign(b"picnic message")
        return public_key, signature


def rainbow_vulnerable_signature():
    """Rainbow signature scheme (VULNERABLE - broken)"""
    # Rainbow has been broken and should not be used
    with oqs.Signature("Rainbow-I-Classic") as signer:
        public_key = signer.generate_keypair()
        return public_key


def gemss_signature_example():
    """GeMSS - Great Multivariate Signature Scheme"""
    with oqs.Signature("GeMSS-128") as signer:
        keypair = signer.generate_keypair()
        return keypair
