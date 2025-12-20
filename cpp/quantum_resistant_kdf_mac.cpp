// Quantum Resistant - KDF and MAC
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <vector>
#include <memory>
#include <cstring>
#include <stdexcept>

namespace pqc {

// KDF Functions
class HkdfDerive {
public:
    std::vector<uint8_t> derive(const std::vector<uint8_t>& ikm,
                                 const std::vector<uint8_t>& salt,
                                 const std::vector<uint8_t>& info,
                                 size_t length = 32) {
        EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr);
        std::vector<uint8_t> okm(length);

        EVP_PKEY_derive_init(pctx);
        EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha256());
        EVP_PKEY_CTX_set1_hkdf_salt(pctx, salt.data(), salt.size());
        EVP_PKEY_CTX_set1_hkdf_key(pctx, ikm.data(), ikm.size());
        EVP_PKEY_CTX_add1_hkdf_info(pctx, info.data(), info.size());

        size_t outLen = length;
        EVP_PKEY_derive(pctx, okm.data(), &outLen);
        EVP_PKEY_CTX_free(pctx);

        return okm;
    }
};

class Pbkdf2Derive {
public:
    std::vector<uint8_t> derive(const std::string& password,
                                 const std::vector<uint8_t>& salt,
                                 int iterations = 100000,
                                 size_t keyLen = 32) {
        std::vector<uint8_t> key(keyLen);
        PKCS5_PBKDF2_HMAC(password.c_str(), password.size(),
                          salt.data(), salt.size(),
                          iterations, EVP_sha256(), keyLen, key.data());
        return key;
    }
};

class ScryptDerive {
public:
    std::vector<uint8_t> derive(const std::string& password,
                                 const std::vector<uint8_t>& salt,
                                 size_t keyLen = 32) {
        EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_SCRYPT, nullptr);
        std::vector<uint8_t> key(keyLen);

        EVP_PKEY_derive_init(pctx);
        EVP_PKEY_CTX_set1_pbe_pass(pctx, password.c_str(), password.size());
        EVP_PKEY_CTX_set1_scrypt_salt(pctx, salt.data(), salt.size());
        EVP_PKEY_CTX_set_scrypt_N(pctx, 16384);
        EVP_PKEY_CTX_set_scrypt_r(pctx, 8);
        EVP_PKEY_CTX_set_scrypt_p(pctx, 1);

        size_t outLen = keyLen;
        EVP_PKEY_derive(pctx, key.data(), &outLen);
        EVP_PKEY_CTX_free(pctx);

        return key;
    }
};

class Argon2Derive {
public:
    std::vector<uint8_t> derive(const std::string& password,
                                 const std::vector<uint8_t>& salt,
                                 size_t keyLen = 32) {
        // Argon2id implementation
        EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ARGON2ID, nullptr);
        if (!pctx) throw std::runtime_error("Argon2 not available");

        std::vector<uint8_t> key(keyLen);
        EVP_PKEY_derive_init(pctx);

        size_t outLen = keyLen;
        EVP_PKEY_derive(pctx, key.data(), &outLen);
        EVP_PKEY_CTX_free(pctx);

        return key;
    }
};

// MAC Functions
class HmacSha256Mac {
public:
    std::vector<uint8_t> mac(const std::vector<uint8_t>& key,
                              const std::vector<uint8_t>& message) {
        std::vector<uint8_t> result(32);
        unsigned int len;
        HMAC(EVP_sha256(), key.data(), key.size(),
             message.data(), message.size(), result.data(), &len);
        return result;
    }
};

class HmacSha512Mac {
public:
    std::vector<uint8_t> mac(const std::vector<uint8_t>& key,
                              const std::vector<uint8_t>& message) {
        std::vector<uint8_t> result(64);
        unsigned int len;
        HMAC(EVP_sha512(), key.data(), key.size(),
             message.data(), message.size(), result.data(), &len);
        return result;
    }
};

class Poly1305Mac {
public:
    std::vector<uint8_t> mac(const std::vector<uint8_t>& key,
                              const std::vector<uint8_t>& message) {
        EVP_MAC* evp_mac = EVP_MAC_fetch(nullptr, "POLY1305", nullptr);
        EVP_MAC_CTX* ctx = EVP_MAC_CTX_new(evp_mac);
        std::vector<uint8_t> result(16);
        size_t len = 16;

        EVP_MAC_init(ctx, key.data(), 32, nullptr);
        EVP_MAC_update(ctx, message.data(), message.size());
        EVP_MAC_final(ctx, result.data(), &len, 16);

        EVP_MAC_CTX_free(ctx);
        EVP_MAC_free(evp_mac);
        return result;
    }
};

} // namespace pqc
