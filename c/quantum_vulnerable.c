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
#include <string.h>
#include <stdlib.h>

// Broken Hash (VULNERABLE)
void md5_broken_hash(const unsigned char *data, size_t len, unsigned char *hash) {
    MD5(data, len, hash);
}

void md4_broken_hash(const unsigned char *data, size_t len, unsigned char *hash) {
    MD4(data, len, hash);
}

void sha1_broken_hash(const unsigned char *data, size_t len, unsigned char *hash) {
    SHA1(data, len, hash);
}

void ripemd_weak_hash(const unsigned char *data, size_t len, unsigned char *hash) {
    RIPEMD160(data, len, hash);
}

// Weak Symmetric (VULNERABLE)
int des_weak_cipher(const unsigned char *plaintext, int len,
                    const unsigned char *key, unsigned char *ciphertext) {
    DES_cblock des_key;
    DES_key_schedule schedule;

    memcpy(des_key, key, 8);
    DES_set_key_unchecked(&des_key, &schedule);
    DES_ecb_encrypt((DES_cblock*)plaintext, (DES_cblock*)ciphertext, &schedule, DES_ENCRYPT);
    return 0;
}

int triple_des_3des_cipher(const unsigned char *plaintext, int len,
                           const unsigned char *key, unsigned char *ciphertext) {
    DES_cblock key1, key2, key3;
    DES_key_schedule ks1, ks2, ks3;
    DES_cblock iv = {0};

    memcpy(key1, key, 8);
    memcpy(key2, key + 8, 8);
    memcpy(key3, key + 16, 8);

    DES_set_key_unchecked(&key1, &ks1);
    DES_set_key_unchecked(&key2, &ks2);
    DES_set_key_unchecked(&key3, &ks3);

    DES_ede3_cbc_encrypt(plaintext, ciphertext, len, &ks1, &ks2, &ks3, &iv, DES_ENCRYPT);
    return 0;
}

int rc4_stream_cipher(const unsigned char *plaintext, int len,
                      const unsigned char *key, int key_len, unsigned char *ciphertext) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int out_len;

    EVP_EncryptInit_ex(ctx, EVP_rc4(), NULL, key, NULL);
    EVP_EncryptUpdate(ctx, ciphertext, &out_len, plaintext, len);

    EVP_CIPHER_CTX_free(ctx);
    return out_len;
}

int blowfish_cipher(const unsigned char *plaintext, int len,
                    const unsigned char *key, int key_len, unsigned char *ciphertext) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    unsigned char iv[8] = {0};
    int out_len;

    EVP_EncryptInit_ex(ctx, EVP_bf_cbc(), NULL, key, iv);
    EVP_EncryptUpdate(ctx, ciphertext, &out_len, plaintext, len);

    EVP_CIPHER_CTX_free(ctx);
    return out_len;
}

int idea_cipher(const unsigned char *plaintext, int len,
                const unsigned char *key, unsigned char *ciphertext) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    unsigned char iv[8] = {0};
    int out_len;

    EVP_EncryptInit_ex(ctx, EVP_idea_cbc(), NULL, key, iv);
    EVP_EncryptUpdate(ctx, ciphertext, &out_len, plaintext, len);

    EVP_CIPHER_CTX_free(ctx);
    return out_len;
}

// Weak MAC (VULNERABLE)
int hmac_md5_weak(const unsigned char *key, int key_len,
                  const unsigned char *data, int data_len, unsigned char *mac) {
    unsigned int mac_len;
    HMAC(EVP_md5(), key, key_len, data, data_len, mac, &mac_len);
    return mac_len;
}

int hmac_sha1_weak(const unsigned char *key, int key_len,
                   const unsigned char *data, int data_len, unsigned char *mac) {
    unsigned int mac_len;
    HMAC(EVP_sha1(), key, key_len, data, data_len, mac, &mac_len);
    return mac_len;
}

// Shor Vulnerable - Asymmetric (VULNERABLE to quantum computers)
RSA* rsa_encryption(void) {
    RSA *rsa = RSA_new();
    BIGNUM *e = BN_new();
    BN_set_word(e, RSA_F4);
    RSA_generate_key_ex(rsa, 2048, e, NULL);
    BN_free(e);
    return rsa;
}

DSA* dsa_signature(void) {
    DSA *dsa = DSA_new();
    DSA_generate_parameters_ex(dsa, 2048, NULL, 0, NULL, NULL, NULL);
    DSA_generate_key(dsa);
    return dsa;
}

EC_KEY* ecdsa_signature(void) {
    EC_KEY *ec_key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    EC_KEY_generate_key(ec_key);
    return ec_key;
}

DH* diffie_hellman_key_exchange(void) {
    DH *dh = DH_new();
    DH_generate_parameters_ex(dh, 2048, DH_GENERATOR_2, NULL);
    DH_generate_key(dh);
    return dh;
}

EC_KEY* ecdh_key_exchange(void) {
    EC_KEY *ec_key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    EC_KEY_generate_key(ec_key);
    return ec_key;
}

// Vulnerable Curves
EC_KEY* secp256k1_curve(void) {
    EC_KEY *ec_key = EC_KEY_new_by_curve_name(NID_secp256k1);
    EC_KEY_generate_key(ec_key);
    return ec_key;
}

EC_KEY* p384_curve(void) {
    EC_KEY *ec_key = EC_KEY_new_by_curve_name(NID_secp384r1);
    EC_KEY_generate_key(ec_key);
    return ec_key;
}

EC_KEY* p521_curve(void) {
    EC_KEY *ec_key = EC_KEY_new_by_curve_name(NID_secp521r1);
    EC_KEY_generate_key(ec_key);
    return ec_key;
}

EVP_PKEY* curve25519_key(void) {
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
    EVP_PKEY_keygen_init(pctx);
    EVP_PKEY_keygen(pctx, &pkey);
    EVP_PKEY_CTX_free(pctx);
    return pkey;
}

EVP_PKEY* ed25519_signature(void) {
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, NULL);
    EVP_PKEY_keygen_init(pctx);
    EVP_PKEY_keygen(pctx, &pkey);
    EVP_PKEY_CTX_free(pctx);
    return pkey;
}
