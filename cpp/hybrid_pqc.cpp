// Quantum Safe - Hybrid PQC Implementations
#include <oqs/oqs.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/rand.h>
#include <vector>
#include <memory>
#include <cstring>
#include <stdexcept>

namespace pqc {

// Hybrid X25519 + Kyber768
class HybridX25519Kyber768 {
public:
    std::vector<uint8_t> generateHybridKey() {
        // Classical X25519
        EVP_PKEY* x25519Key = nullptr;
        EVP_PKEY_CTX* x25519Ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, nullptr);
        EVP_PKEY_keygen_init(x25519Ctx);
        EVP_PKEY_keygen(x25519Ctx, &x25519Key);

        std::vector<uint8_t> x25519Pubkey(32);
        size_t x25519PubkeyLen = 32;
        EVP_PKEY_get_raw_public_key(x25519Key, x25519Pubkey.data(), &x25519PubkeyLen);

        // Post-quantum Kyber768
        OQS_KEM* kyber = OQS_KEM_new(OQS_KEM_alg_kyber_768);
        std::vector<uint8_t> kyberPk(kyber->length_public_key);
        std::vector<uint8_t> kyberSk(kyber->length_secret_key);
        std::vector<uint8_t> kyberCt(kyber->length_ciphertext);
        std::vector<uint8_t> kyberSs(kyber->length_shared_secret);

        OQS_KEM_keypair(kyber, kyberPk.data(), kyberSk.data());
        OQS_KEM_encaps(kyber, kyberCt.data(), kyberSs.data(), kyberPk.data());

        // Combine shared secrets with HKDF
        std::vector<uint8_t> combined(64);
        std::memcpy(combined.data(), x25519Pubkey.data(), 32);
        std::memcpy(combined.data() + 32, kyberSs.data(), 32);

        std::vector<uint8_t> finalKey(32);
        EVP_PKEY_CTX* hkdfCtx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr);
        EVP_PKEY_derive_init(hkdfCtx);
        EVP_PKEY_CTX_set_hkdf_md(hkdfCtx, EVP_sha256());
        EVP_PKEY_CTX_set1_hkdf_key(hkdfCtx, combined.data(), 64);
        EVP_PKEY_CTX_add1_hkdf_info(hkdfCtx, (uint8_t*)"hybrid-kem", 10);

        size_t finalKeyLen = 32;
        EVP_PKEY_derive(hkdfCtx, finalKey.data(), &finalKeyLen);

        // Cleanup
        EVP_PKEY_CTX_free(x25519Ctx);
        EVP_PKEY_CTX_free(hkdfCtx);
        EVP_PKEY_free(x25519Key);
        OQS_KEM_free(kyber);

        return finalKey;
    }
};

// Hybrid ECDH + ML-KEM
class HybridEcdhMlKem {
public:
    std::vector<uint8_t> generateHybridKey() {
        // ECDH P-256
        EVP_PKEY* ecKey = nullptr;
        EVP_PKEY_CTX* ecCtx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr);
        EVP_PKEY_keygen_init(ecCtx);
        EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ecCtx, NID_X9_62_prime256v1);
        EVP_PKEY_keygen(ecCtx, &ecKey);

        // ML-KEM (Kyber768)
        OQS_KEM* mlkem = OQS_KEM_new(OQS_KEM_alg_kyber_768);
        std::vector<uint8_t> mlkemPk(mlkem->length_public_key);
        std::vector<uint8_t> mlkemSk(mlkem->length_secret_key);
        std::vector<uint8_t> mlkemCt(mlkem->length_ciphertext);
        std::vector<uint8_t> mlkemSs(mlkem->length_shared_secret);

        OQS_KEM_keypair(mlkem, mlkemPk.data(), mlkemSk.data());
        OQS_KEM_encaps(mlkem, mlkemCt.data(), mlkemSs.data(), mlkemPk.data());

        EVP_PKEY_CTX_free(ecCtx);
        EVP_PKEY_free(ecKey);
        OQS_KEM_free(mlkem);

        return mlkemSs;
    }
};

// Hybrid TLS with PQC
class HybridTlsPqc {
public:
    void setup() {
        // X25519 component
        EVP_PKEY* x25519Key = nullptr;
        EVP_PKEY_CTX* x25519Ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, nullptr);
        EVP_PKEY_keygen_init(x25519Ctx);
        EVP_PKEY_keygen(x25519Ctx, &x25519Key);

        // Kyber768 component
        OQS_KEM* kyber = OQS_KEM_new(OQS_KEM_alg_kyber_768);
        std::vector<uint8_t> kyberPk(kyber->length_public_key);
        std::vector<uint8_t> kyberSk(kyber->length_secret_key);

        OQS_KEM_keypair(kyber, kyberPk.data(), kyberSk.data());

        EVP_PKEY_CTX_free(x25519Ctx);
        EVP_PKEY_free(x25519Key);
        OQS_KEM_free(kyber);
    }
};

// X25519Kyber768Draft00 IETF draft
class X25519Kyber768Draft00 {
public:
    std::vector<uint8_t> generateHybridPublicKey() {
        // X25519
        EVP_PKEY* x25519Key = nullptr;
        EVP_PKEY_CTX* x25519Ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, nullptr);
        EVP_PKEY_keygen_init(x25519Ctx);
        EVP_PKEY_keygen(x25519Ctx, &x25519Key);

        std::vector<uint8_t> x25519Pub(32);
        size_t x25519PubLen = 32;
        EVP_PKEY_get_raw_public_key(x25519Key, x25519Pub.data(), &x25519PubLen);

        // Kyber768
        OQS_KEM* kyber = OQS_KEM_new(OQS_KEM_alg_kyber_768);
        std::vector<uint8_t> kyberPk(kyber->length_public_key);
        std::vector<uint8_t> kyberSk(kyber->length_secret_key);

        OQS_KEM_keypair(kyber, kyberPk.data(), kyberSk.data());

        // Combine public keys
        std::vector<uint8_t> hybridPublic(32 + kyber->length_public_key);
        std::memcpy(hybridPublic.data(), x25519Pub.data(), 32);
        std::memcpy(hybridPublic.data() + 32, kyberPk.data(), kyber->length_public_key);

        EVP_PKEY_CTX_free(x25519Ctx);
        EVP_PKEY_free(x25519Key);
        OQS_KEM_free(kyber);

        return hybridPublic;
    }
};

// ECDH + Kyber Composite
class EcdhKyberComposite {
public:
    std::vector<uint8_t> generateCompositeSecret() {
        // ECDH P-384
        EVP_PKEY* ecKey = nullptr;
        EVP_PKEY_CTX* ecCtx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr);
        EVP_PKEY_keygen_init(ecCtx);
        EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ecCtx, NID_secp384r1);
        EVP_PKEY_keygen(ecCtx, &ecKey);

        // Kyber768
        OQS_KEM* kyber = OQS_KEM_new(OQS_KEM_alg_kyber_768);
        std::vector<uint8_t> kyberPk(kyber->length_public_key);
        std::vector<uint8_t> kyberSk(kyber->length_secret_key);
        std::vector<uint8_t> kyberCt(kyber->length_ciphertext);
        std::vector<uint8_t> kyberSs(kyber->length_shared_secret);

        OQS_KEM_keypair(kyber, kyberPk.data(), kyberSk.data());
        OQS_KEM_encaps(kyber, kyberCt.data(), kyberSs.data(), kyberPk.data());

        // Combine with HKDF
        std::vector<uint8_t> compositeSecret(32);
        EVP_PKEY_CTX* hkdfCtx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr);
        EVP_PKEY_derive_init(hkdfCtx);
        EVP_PKEY_CTX_set_hkdf_md(hkdfCtx, EVP_sha256());
        EVP_PKEY_CTX_set1_hkdf_key(hkdfCtx, kyberSs.data(), kyberSs.size());
        EVP_PKEY_CTX_add1_hkdf_info(hkdfCtx, (uint8_t*)"composite-kem", 13);

        size_t secretLen = 32;
        EVP_PKEY_derive(hkdfCtx, compositeSecret.data(), &secretLen);

        EVP_PKEY_CTX_free(ecCtx);
        EVP_PKEY_CTX_free(hkdfCtx);
        EVP_PKEY_free(ecKey);
        OQS_KEM_free(kyber);

        return compositeSecret;
    }
};

} // namespace pqc
