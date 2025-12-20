// Quantum Vulnerable - Broken/Weak Algorithms (DO NOT USE IN PRODUCTION)
#include <openssl/evp.h>
#include <openssl/md5.h>
#include <openssl/md4.h>
#include <openssl/sha.h>
#include <openssl/des.h>
#include <openssl/blowfish.h>
#include <openssl/rc4.h>
#include <openssl/rsa.h>
#include <openssl/dsa.h>
#include <openssl/ec.h>
#include <openssl/dh.h>
#include <openssl/hmac.h>
#include <openssl/ripemd.h>
#include <vector>
#include <memory>
#include <cstring>

namespace pqc {

// Broken Hash (VULNERABLE)
class Md5BrokenHash {
public:
    std::vector<uint8_t> hash(const std::vector<uint8_t>& data) {
        std::vector<uint8_t> digest(MD5_DIGEST_LENGTH);
        MD5(data.data(), data.size(), digest.data());
        return digest;
    }
};

class Md4BrokenHash {
public:
    std::vector<uint8_t> hash(const std::vector<uint8_t>& data) {
        std::vector<uint8_t> digest(MD4_DIGEST_LENGTH);
        MD4(data.data(), data.size(), digest.data());
        return digest;
    }
};

class Sha1BrokenHash {
public:
    std::vector<uint8_t> hash(const std::vector<uint8_t>& data) {
        std::vector<uint8_t> digest(SHA_DIGEST_LENGTH);
        SHA1(data.data(), data.size(), digest.data());
        return digest;
    }
};

class RipemdWeakHash {
public:
    std::vector<uint8_t> hash(const std::vector<uint8_t>& data) {
        std::vector<uint8_t> digest(RIPEMD160_DIGEST_LENGTH);
        RIPEMD160(data.data(), data.size(), digest.data());
        return digest;
    }
};

// Weak Symmetric (VULNERABLE)
class DesWeakCipher {
public:
    std::vector<uint8_t> encrypt(const std::vector<uint8_t>& plaintext,
                                  const std::vector<uint8_t>& key) {
        DES_cblock desKey;
        DES_key_schedule schedule;
        std::vector<uint8_t> ciphertext(8);

        std::memcpy(desKey, key.data(), 8);
        DES_set_key_unchecked(&desKey, &schedule);
        DES_ecb_encrypt((DES_cblock*)plaintext.data(),
                        (DES_cblock*)ciphertext.data(), &schedule, DES_ENCRYPT);
        return ciphertext;
    }
};

class TripleDes3desCipher {
public:
    std::vector<uint8_t> encrypt(const std::vector<uint8_t>& plaintext,
                                  const std::vector<uint8_t>& key) {
        DES_cblock key1, key2, key3;
        DES_key_schedule ks1, ks2, ks3;
        DES_cblock iv = {0};
        std::vector<uint8_t> ciphertext(plaintext.size());

        std::memcpy(key1, key.data(), 8);
        std::memcpy(key2, key.data() + 8, 8);
        std::memcpy(key3, key.data() + 16, 8);

        DES_set_key_unchecked(&key1, &ks1);
        DES_set_key_unchecked(&key2, &ks2);
        DES_set_key_unchecked(&key3, &ks3);

        DES_ede3_cbc_encrypt(plaintext.data(), ciphertext.data(),
                             plaintext.size(), &ks1, &ks2, &ks3, &iv, DES_ENCRYPT);
        return ciphertext;
    }
};

class Rc4StreamCipher {
public:
    std::vector<uint8_t> encrypt(const std::vector<uint8_t>& plaintext,
                                  const std::vector<uint8_t>& key) {
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        std::vector<uint8_t> ciphertext(plaintext.size());
        int len;

        EVP_EncryptInit_ex(ctx, EVP_rc4(), nullptr, key.data(), nullptr);
        EVP_EncryptUpdate(ctx, ciphertext.data(), &len, plaintext.data(), plaintext.size());

        EVP_CIPHER_CTX_free(ctx);
        return ciphertext;
    }
};

class BlowfishCipher {
public:
    std::vector<uint8_t> encrypt(const std::vector<uint8_t>& plaintext,
                                  const std::vector<uint8_t>& key) {
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        std::vector<uint8_t> iv(8, 0);
        std::vector<uint8_t> ciphertext(plaintext.size() + 8);
        int len;

        EVP_EncryptInit_ex(ctx, EVP_bf_cbc(), nullptr, key.data(), iv.data());
        EVP_EncryptUpdate(ctx, ciphertext.data(), &len, plaintext.data(), plaintext.size());

        EVP_CIPHER_CTX_free(ctx);
        return ciphertext;
    }
};

// Weak MAC (VULNERABLE)
class HmacMd5Weak {
public:
    std::vector<uint8_t> mac(const std::vector<uint8_t>& key,
                              const std::vector<uint8_t>& message) {
        std::vector<uint8_t> result(16);
        unsigned int len;
        HMAC(EVP_md5(), key.data(), key.size(),
             message.data(), message.size(), result.data(), &len);
        return result;
    }
};

class HmacSha1Weak {
public:
    std::vector<uint8_t> mac(const std::vector<uint8_t>& key,
                              const std::vector<uint8_t>& message) {
        std::vector<uint8_t> result(20);
        unsigned int len;
        HMAC(EVP_sha1(), key.data(), key.size(),
             message.data(), message.size(), result.data(), &len);
        return result;
    }
};

// Shor Vulnerable - Asymmetric (VULNERABLE to quantum computers)
class RsaEncryption {
public:
    RSA* generateKeypair() {
        RSA* rsa = RSA_new();
        BIGNUM* e = BN_new();
        BN_set_word(e, RSA_F4);
        RSA_generate_key_ex(rsa, 2048, e, nullptr);
        BN_free(e);
        return rsa;
    }
};

class DsaSignature {
public:
    DSA* generateKeypair() {
        DSA* dsa = DSA_new();
        DSA_generate_parameters_ex(dsa, 2048, nullptr, 0, nullptr, nullptr, nullptr);
        DSA_generate_key(dsa);
        return dsa;
    }
};

class EcdsaSignature {
public:
    EC_KEY* generateKeypair() {
        EC_KEY* ecKey = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
        EC_KEY_generate_key(ecKey);
        return ecKey;
    }
};

class DiffieHellmanKeyExchange {
public:
    DH* generateKeypair() {
        DH* dh = DH_new();
        DH_generate_parameters_ex(dh, 2048, DH_GENERATOR_2, nullptr);
        DH_generate_key(dh);
        return dh;
    }
};

class EcdhKeyExchange {
public:
    EC_KEY* generateKeypair() {
        EC_KEY* ecKey = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
        EC_KEY_generate_key(ecKey);
        return ecKey;
    }
};

// Vulnerable Curves
class Secp256k1Curve {
public:
    EC_KEY* generateKeypair() {
        EC_KEY* ecKey = EC_KEY_new_by_curve_name(NID_secp256k1);
        EC_KEY_generate_key(ecKey);
        return ecKey;
    }
};

class P384Curve {
public:
    EC_KEY* generateKeypair() {
        EC_KEY* ecKey = EC_KEY_new_by_curve_name(NID_secp384r1);
        EC_KEY_generate_key(ecKey);
        return ecKey;
    }
};

class P521Curve {
public:
    EC_KEY* generateKeypair() {
        EC_KEY* ecKey = EC_KEY_new_by_curve_name(NID_secp521r1);
        EC_KEY_generate_key(ecKey);
        return ecKey;
    }
};

class Curve25519Key {
public:
    EVP_PKEY* generateKeypair() {
        EVP_PKEY* pkey = nullptr;
        EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, nullptr);
        EVP_PKEY_keygen_init(pctx);
        EVP_PKEY_keygen(pctx, &pkey);
        EVP_PKEY_CTX_free(pctx);
        return pkey;
    }
};

class Ed25519Signature {
public:
    EVP_PKEY* generateKeypair() {
        EVP_PKEY* pkey = nullptr;
        EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, nullptr);
        EVP_PKEY_keygen_init(pctx);
        EVP_PKEY_keygen(pctx, &pkey);
        EVP_PKEY_CTX_free(pctx);
        return pkey;
    }
};

} // namespace pqc
