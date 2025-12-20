// Quantum Safe - Digital Signatures
#include <oqs/oqs.h>
#include <vector>
#include <memory>
#include <stdexcept>
#include <cstring>

namespace pqc {

// ML-DSA-44 (Dilithium2) Digital Signature
class MlDsa44 {
public:
    std::pair<std::vector<uint8_t>, std::vector<uint8_t>> generateKeypair() {
        OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_dilithium_2);
        if (!sig) throw std::runtime_error("Failed to create Dilithium2");

        std::vector<uint8_t> publicKey(sig->length_public_key);
        std::vector<uint8_t> secretKey(sig->length_secret_key);

        OQS_SIG_keypair(sig, publicKey.data(), secretKey.data());
        OQS_SIG_free(sig);

        return {publicKey, secretKey};
    }

    std::vector<uint8_t> sign(const std::vector<uint8_t>& message,
                               const std::vector<uint8_t>& secretKey) {
        OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_dilithium_2);
        std::vector<uint8_t> signature(sig->length_signature);
        size_t sigLen;

        OQS_SIG_sign(sig, signature.data(), &sigLen, message.data(), message.size(), secretKey.data());
        signature.resize(sigLen);
        OQS_SIG_free(sig);

        return signature;
    }

    bool verify(const std::vector<uint8_t>& message,
                const std::vector<uint8_t>& signature,
                const std::vector<uint8_t>& publicKey) {
        OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_dilithium_2);
        int result = OQS_SIG_verify(sig, message.data(), message.size(),
                                     signature.data(), signature.size(), publicKey.data());
        OQS_SIG_free(sig);
        return result == OQS_SUCCESS;
    }
};

// ML-DSA-65 (Dilithium3) Digital Signature
class MlDsa65 {
public:
    std::pair<std::vector<uint8_t>, std::vector<uint8_t>> generateKeypair() {
        OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_dilithium_3);
        std::vector<uint8_t> pk(sig->length_public_key);
        std::vector<uint8_t> sk(sig->length_secret_key);

        OQS_SIG_keypair(sig, pk.data(), sk.data());
        OQS_SIG_free(sig);

        return {pk, sk};
    }
};

// ML-DSA-87 (Dilithium5) Digital Signature
class MlDsa87 {
public:
    std::pair<std::vector<uint8_t>, std::vector<uint8_t>> generateKeypair() {
        OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_dilithium_5);
        std::vector<uint8_t> pk(sig->length_public_key);
        std::vector<uint8_t> sk(sig->length_secret_key);

        OQS_SIG_keypair(sig, pk.data(), sk.data());
        OQS_SIG_free(sig);

        return {pk, sk};
    }
};

// Falcon-512 Digital Signature
class Falcon512 {
public:
    std::pair<std::vector<uint8_t>, std::vector<uint8_t>> generateKeypair() {
        OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_falcon_512);
        std::vector<uint8_t> pk(sig->length_public_key);
        std::vector<uint8_t> sk(sig->length_secret_key);

        OQS_SIG_keypair(sig, pk.data(), sk.data());
        OQS_SIG_free(sig);

        return {pk, sk};
    }

    std::vector<uint8_t> sign(const std::vector<uint8_t>& message,
                               const std::vector<uint8_t>& secretKey) {
        OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_falcon_512);
        std::vector<uint8_t> signature(sig->length_signature);
        size_t sigLen;

        OQS_SIG_sign(sig, signature.data(), &sigLen, message.data(), message.size(), secretKey.data());
        signature.resize(sigLen);
        OQS_SIG_free(sig);

        return signature;
    }
};

// SLH-DSA (SPHINCS+) Digital Signature
class SlhDsaSphincsPlus {
public:
    std::pair<std::vector<uint8_t>, std::vector<uint8_t>> generateKeypair() {
        OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_sphincs_shake_128f_simple);
        std::vector<uint8_t> pk(sig->length_public_key);
        std::vector<uint8_t> sk(sig->length_secret_key);

        OQS_SIG_keypair(sig, pk.data(), sk.data());
        OQS_SIG_free(sig);

        return {pk, sk};
    }
};

// XMSS Hash-based Signature
class XmssSignature {
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

// LMS Hash-based Signature
class LmsSignature {
public:
    std::pair<std::vector<uint8_t>, std::vector<uint8_t>> generateKeypair() {
        OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_dilithium_3);
        std::vector<uint8_t> pk(sig->length_public_key);
        std::vector<uint8_t> sk(sig->length_secret_key);

        OQS_SIG_keypair(sig, pk.data(), sk.data());
        OQS_SIG_free(sig);

        return {pk, sk};
    }
};

} // namespace pqc
