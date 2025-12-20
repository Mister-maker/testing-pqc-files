// Quantum Resistant - Strong Symmetric Encryption and Hashes
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <vector>
#include <memory>
#include <cstring>
#include <stdexcept>

namespace pqc {

// Strong Symmetric (256-bit)
class Aes256Gcm {
public:
    std::vector<uint8_t> encrypt(const std::vector<uint8_t>& plaintext,
                                  const std::vector<uint8_t>& key) {
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        std::vector<uint8_t> iv(12);
        std::vector<uint8_t> ciphertext(plaintext.size() + 16);
        std::vector<uint8_t> tag(16);
        int len, ciphertext_len;

        RAND_bytes(iv.data(), 12);
        EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, key.data(), iv.data());
        EVP_EncryptUpdate(ctx, ciphertext.data(), &len, plaintext.data(), plaintext.size());
        ciphertext_len = len;
        EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len);
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag.data());

        EVP_CIPHER_CTX_free(ctx);
        ciphertext.resize(ciphertext_len);
        return ciphertext;
    }
};

class ChaCha20Poly1305 {
public:
    std::vector<uint8_t> encrypt(const std::vector<uint8_t>& plaintext,
                                  const std::vector<uint8_t>& key) {
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        std::vector<uint8_t> iv(12);
        std::vector<uint8_t> ciphertext(plaintext.size() + 16);
        int len;

        RAND_bytes(iv.data(), 12);
        EVP_EncryptInit_ex(ctx, EVP_chacha20_poly1305(), nullptr, key.data(), iv.data());
        EVP_EncryptUpdate(ctx, ciphertext.data(), &len, plaintext.data(), plaintext.size());
        EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len);

        EVP_CIPHER_CTX_free(ctx);
        return ciphertext;
    }
};

// Strong Symmetric (192-bit)
class Aes192Gcm {
public:
    std::vector<uint8_t> encrypt(const std::vector<uint8_t>& plaintext,
                                  const std::vector<uint8_t>& key) {
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        std::vector<uint8_t> iv(12);
        std::vector<uint8_t> ciphertext(plaintext.size() + 16);
        int len;

        RAND_bytes(iv.data(), 12);
        EVP_EncryptInit_ex(ctx, EVP_aes_192_gcm(), nullptr, key.data(), iv.data());
        EVP_EncryptUpdate(ctx, ciphertext.data(), &len, plaintext.data(), plaintext.size());

        EVP_CIPHER_CTX_free(ctx);
        return ciphertext;
    }
};

// Strong Hash (512-bit)
class Sha512Hash {
public:
    std::vector<uint8_t> hash(const std::vector<uint8_t>& data) {
        std::vector<uint8_t> digest(SHA512_DIGEST_LENGTH);
        SHA512(data.data(), data.size(), digest.data());
        return digest;
    }
};

class Sha3_512Hash {
public:
    std::vector<uint8_t> hash(const std::vector<uint8_t>& data) {
        EVP_MD_CTX* ctx = EVP_MD_CTX_new();
        std::vector<uint8_t> digest(64);
        unsigned int len;

        EVP_DigestInit_ex(ctx, EVP_sha3_512(), nullptr);
        EVP_DigestUpdate(ctx, data.data(), data.size());
        EVP_DigestFinal_ex(ctx, digest.data(), &len);
        EVP_MD_CTX_free(ctx);

        return digest;
    }
};

// Strong Hash (384-bit)
class Sha384Hash {
public:
    std::vector<uint8_t> hash(const std::vector<uint8_t>& data) {
        std::vector<uint8_t> digest(SHA384_DIGEST_LENGTH);
        SHA384(data.data(), data.size(), digest.data());
        return digest;
    }
};

class Sha3_384Hash {
public:
    std::vector<uint8_t> hash(const std::vector<uint8_t>& data) {
        EVP_MD_CTX* ctx = EVP_MD_CTX_new();
        std::vector<uint8_t> digest(48);
        unsigned int len;

        EVP_DigestInit_ex(ctx, EVP_sha3_384(), nullptr);
        EVP_DigestUpdate(ctx, data.data(), data.size());
        EVP_DigestFinal_ex(ctx, digest.data(), &len);
        EVP_MD_CTX_free(ctx);

        return digest;
    }
};

// Strong Hash (256-bit)
class Sha256Hash {
public:
    std::vector<uint8_t> hash(const std::vector<uint8_t>& data) {
        std::vector<uint8_t> digest(SHA256_DIGEST_LENGTH);
        SHA256(data.data(), data.size(), digest.data());
        return digest;
    }
};

class Sha3_256Hash {
public:
    std::vector<uint8_t> hash(const std::vector<uint8_t>& data) {
        EVP_MD_CTX* ctx = EVP_MD_CTX_new();
        std::vector<uint8_t> digest(32);
        unsigned int len;

        EVP_DigestInit_ex(ctx, EVP_sha3_256(), nullptr);
        EVP_DigestUpdate(ctx, data.data(), data.size());
        EVP_DigestFinal_ex(ctx, digest.data(), &len);
        EVP_MD_CTX_free(ctx);

        return digest;
    }
};

class Blake2bHash {
public:
    std::vector<uint8_t> hash(const std::vector<uint8_t>& data) {
        EVP_MD_CTX* ctx = EVP_MD_CTX_new();
        std::vector<uint8_t> digest(64);
        unsigned int len;

        EVP_DigestInit_ex(ctx, EVP_blake2b512(), nullptr);
        EVP_DigestUpdate(ctx, data.data(), data.size());
        EVP_DigestFinal_ex(ctx, digest.data(), &len);
        EVP_MD_CTX_free(ctx);

        return digest;
    }
};

// Strong Hash (Variable - XOF)
class Shake128Xof {
public:
    std::vector<uint8_t> hash(const std::vector<uint8_t>& data, size_t outputLen = 32) {
        EVP_MD_CTX* ctx = EVP_MD_CTX_new();
        std::vector<uint8_t> output(outputLen);

        EVP_DigestInit_ex(ctx, EVP_shake128(), nullptr);
        EVP_DigestUpdate(ctx, data.data(), data.size());
        EVP_DigestFinalXOF(ctx, output.data(), outputLen);
        EVP_MD_CTX_free(ctx);

        return output;
    }
};

class Shake256Xof {
public:
    std::vector<uint8_t> hash(const std::vector<uint8_t>& data, size_t outputLen = 64) {
        EVP_MD_CTX* ctx = EVP_MD_CTX_new();
        std::vector<uint8_t> output(outputLen);

        EVP_DigestInit_ex(ctx, EVP_shake256(), nullptr);
        EVP_DigestUpdate(ctx, data.data(), data.size());
        EVP_DigestFinalXOF(ctx, output.data(), outputLen);
        EVP_MD_CTX_free(ctx);

        return output;
    }
};

} // namespace pqc
