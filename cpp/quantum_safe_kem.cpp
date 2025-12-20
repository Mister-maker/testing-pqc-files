// Quantum Safe - Key Encapsulation Mechanisms (KEM)
#include <oqs/oqs.h>
#include <vector>
#include <memory>
#include <stdexcept>
#include <cstring>

namespace pqc {

// ML-KEM-768 (Kyber768) Key Encapsulation
class MlKem768 {
public:
    std::pair<std::vector<uint8_t>, std::vector<uint8_t>> generateKeypair() {
        OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_kyber_768);
        if (!kem) throw std::runtime_error("Failed to create Kyber768 KEM");

        std::vector<uint8_t> publicKey(kem->length_public_key);
        std::vector<uint8_t> secretKey(kem->length_secret_key);

        OQS_KEM_keypair(kem, publicKey.data(), secretKey.data());
        OQS_KEM_free(kem);

        return {publicKey, secretKey};
    }

    std::pair<std::vector<uint8_t>, std::vector<uint8_t>> encapsulate(const std::vector<uint8_t>& publicKey) {
        OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_kyber_768);
        std::vector<uint8_t> ciphertext(kem->length_ciphertext);
        std::vector<uint8_t> sharedSecret(kem->length_shared_secret);

        OQS_KEM_encaps(kem, ciphertext.data(), sharedSecret.data(), publicKey.data());
        OQS_KEM_free(kem);

        return {ciphertext, sharedSecret};
    }

    std::vector<uint8_t> decapsulate(const std::vector<uint8_t>& ciphertext,
                                      const std::vector<uint8_t>& secretKey) {
        OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_kyber_768);
        std::vector<uint8_t> sharedSecret(kem->length_shared_secret);

        OQS_KEM_decaps(kem, sharedSecret.data(), ciphertext.data(), secretKey.data());
        OQS_KEM_free(kem);

        return sharedSecret;
    }
};

// ML-KEM-1024 (Kyber1024) Key Encapsulation
class MlKem1024 {
public:
    std::pair<std::vector<uint8_t>, std::vector<uint8_t>> generateKeypair() {
        OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_kyber_1024);
        std::vector<uint8_t> pk(kem->length_public_key);
        std::vector<uint8_t> sk(kem->length_secret_key);

        OQS_KEM_keypair(kem, pk.data(), sk.data());
        OQS_KEM_free(kem);

        return {pk, sk};
    }
};

// ML-KEM-512 (Kyber512) Key Encapsulation
class MlKem512 {
public:
    std::pair<std::vector<uint8_t>, std::vector<uint8_t>> generateKeypair() {
        OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_kyber_512);
        std::vector<uint8_t> pk(kem->length_public_key);
        std::vector<uint8_t> sk(kem->length_secret_key);

        OQS_KEM_keypair(kem, pk.data(), sk.data());
        OQS_KEM_free(kem);

        return {pk, sk};
    }
};

// FrodoKEM Key Encapsulation
class FrodoKem {
public:
    std::pair<std::vector<uint8_t>, std::vector<uint8_t>> generateKeypair() {
        OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_frodokem_640_shake);
        std::vector<uint8_t> pk(kem->length_public_key);
        std::vector<uint8_t> sk(kem->length_secret_key);

        OQS_KEM_keypair(kem, pk.data(), sk.data());
        OQS_KEM_free(kem);

        return {pk, sk};
    }
};

// Kyber Key Generation helper
std::pair<std::vector<uint8_t>, std::vector<uint8_t>> kyberKeyGeneration() {
    MlKem768 kyber;
    return kyber.generateKeypair();
}

} // namespace pqc
