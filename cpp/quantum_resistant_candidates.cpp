// Quantum Resistant - PQC Candidates (KEM and Signatures)
#include <oqs/oqs.h>
#include <vector>
#include <memory>
#include <stdexcept>

namespace pqc {

// PQC Candidate KEMs

// NTRU Key Encapsulation
class NtruKem {
public:
    std::pair<std::vector<uint8_t>, std::vector<uint8_t>> generateKeypair() {
        OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_ntru_hps2048509);
        if (!kem) throw std::runtime_error("Failed to create NTRU KEM");

        std::vector<uint8_t> pk(kem->length_public_key);
        std::vector<uint8_t> sk(kem->length_secret_key);

        OQS_KEM_keypair(kem, pk.data(), sk.data());
        OQS_KEM_free(kem);

        return {pk, sk};
    }

    std::pair<std::vector<uint8_t>, std::vector<uint8_t>> encapsulate(const std::vector<uint8_t>& pk) {
        OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_ntru_hps2048509);
        std::vector<uint8_t> ct(kem->length_ciphertext);
        std::vector<uint8_t> ss(kem->length_shared_secret);

        OQS_KEM_encaps(kem, ct.data(), ss.data(), pk.data());
        OQS_KEM_free(kem);

        return {ct, ss};
    }
};

// Classic McEliece Key Encapsulation
class ClassicMcElieceKem {
public:
    std::pair<std::vector<uint8_t>, std::vector<uint8_t>> generateKeypair() {
        OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_classic_mceliece_348864);
        std::vector<uint8_t> pk(kem->length_public_key);
        std::vector<uint8_t> sk(kem->length_secret_key);

        OQS_KEM_keypair(kem, pk.data(), sk.data());
        OQS_KEM_free(kem);

        return {pk, sk};
    }
};

// HQC Key Encapsulation
class HqcKem {
public:
    std::pair<std::vector<uint8_t>, std::vector<uint8_t>> generateKeypair() {
        OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_hqc_128);
        std::vector<uint8_t> pk(kem->length_public_key);
        std::vector<uint8_t> sk(kem->length_secret_key);

        OQS_KEM_keypair(kem, pk.data(), sk.data());
        OQS_KEM_free(kem);

        return {pk, sk};
    }
};

// BIKE Key Encapsulation
class BikeKem {
public:
    std::pair<std::vector<uint8_t>, std::vector<uint8_t>> generateKeypair() {
        OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_bike_l1);
        std::vector<uint8_t> pk(kem->length_public_key);
        std::vector<uint8_t> sk(kem->length_secret_key);

        OQS_KEM_keypair(kem, pk.data(), sk.data());
        OQS_KEM_free(kem);

        return {pk, sk};
    }
};

// SIKE - VULNERABLE (broken)
class SikeVulnerableKem {
public:
    std::pair<std::vector<uint8_t>, std::vector<uint8_t>> generateKeypair() {
        // SIKE has been broken and should not be used
        OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_sike_p434);
        if (!kem) throw std::runtime_error("SIKE not available");

        std::vector<uint8_t> pk(kem->length_public_key);
        std::vector<uint8_t> sk(kem->length_secret_key);

        OQS_KEM_keypair(kem, pk.data(), sk.data());
        OQS_KEM_free(kem);

        return {pk, sk};
    }
};

// PQC Candidate Signatures

// Picnic Signature
class PicnicSignature {
public:
    std::pair<std::vector<uint8_t>, std::vector<uint8_t>> generateKeypair() {
        OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_picnic_L1_full);
        std::vector<uint8_t> pk(sig->length_public_key);
        std::vector<uint8_t> sk(sig->length_secret_key);

        OQS_SIG_keypair(sig, pk.data(), sk.data());
        OQS_SIG_free(sig);

        return {pk, sk};
    }

    std::vector<uint8_t> sign(const std::vector<uint8_t>& message,
                               const std::vector<uint8_t>& sk) {
        OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_picnic_L1_full);
        std::vector<uint8_t> signature(sig->length_signature);
        size_t sigLen;

        OQS_SIG_sign(sig, signature.data(), &sigLen, message.data(), message.size(), sk.data());
        signature.resize(sigLen);
        OQS_SIG_free(sig);

        return signature;
    }
};

// Rainbow - VULNERABLE (broken)
class RainbowVulnerableSignature {
public:
    std::pair<std::vector<uint8_t>, std::vector<uint8_t>> generateKeypair() {
        // Rainbow has been broken and should not be used
        OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_rainbow_I_classic);
        if (!sig) throw std::runtime_error("Rainbow not available");

        std::vector<uint8_t> pk(sig->length_public_key);
        std::vector<uint8_t> sk(sig->length_secret_key);

        OQS_SIG_keypair(sig, pk.data(), sk.data());
        OQS_SIG_free(sig);

        return {pk, sk};
    }
};

// GeMSS Signature
class GemssSignature {
public:
    std::pair<std::vector<uint8_t>, std::vector<uint8_t>> generateKeypair() {
        OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_dilithium_2);
        std::vector<uint8_t> pk(sig->length_public_key);
        std::vector<uint8_t> sk(sig->length_secret_key);

        OQS_SIG_keypair(sig, pk.data(), sk.data());
        OQS_SIG_free(sig);

        return {pk, sk};
    }
};

} // namespace pqc
