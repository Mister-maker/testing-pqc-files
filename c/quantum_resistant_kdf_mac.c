// Quantum Resistant - KDF and MAC
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <string.h>
#include <stdlib.h>

// KDF Functions
int hkdf_derive(const unsigned char *ikm, size_t ikm_len,
                const unsigned char *salt, size_t salt_len,
                const unsigned char *info, size_t info_len,
                unsigned char *okm, size_t okm_len) {
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);

    EVP_PKEY_derive_init(pctx);
    EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha256());
    EVP_PKEY_CTX_set1_hkdf_salt(pctx, salt, salt_len);
    EVP_PKEY_CTX_set1_hkdf_key(pctx, ikm, ikm_len);
    EVP_PKEY_CTX_add1_hkdf_info(pctx, info, info_len);
    EVP_PKEY_derive(pctx, okm, &okm_len);

    EVP_PKEY_CTX_free(pctx);
    return 0;
}

int pbkdf2_derive(const char *password, size_t password_len,
                  const unsigned char *salt, size_t salt_len,
                  int iterations, unsigned char *key, size_t key_len) {
    return PKCS5_PBKDF2_HMAC(password, password_len, salt, salt_len,
                             iterations, EVP_sha256(), key_len, key);
}

int scrypt_derive(const char *password, size_t password_len,
                  const unsigned char *salt, size_t salt_len,
                  unsigned char *key, size_t key_len) {
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_SCRYPT, NULL);

    EVP_PKEY_derive_init(pctx);
    EVP_PKEY_CTX_set1_pbe_pass(pctx, password, password_len);
    EVP_PKEY_CTX_set1_scrypt_salt(pctx, salt, salt_len);
    EVP_PKEY_CTX_set_scrypt_N(pctx, 16384);
    EVP_PKEY_CTX_set_scrypt_r(pctx, 8);
    EVP_PKEY_CTX_set_scrypt_p(pctx, 1);
    EVP_PKEY_derive(pctx, key, &key_len);

    EVP_PKEY_CTX_free(pctx);
    return 0;
}

int argon2_derive(const char *password, size_t password_len,
                  const unsigned char *salt, size_t salt_len,
                  unsigned char *key, size_t key_len) {
    // Argon2id implementation
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ARGON2ID, NULL);
    if (pctx == NULL) return -1;

    EVP_PKEY_derive_init(pctx);
    EVP_PKEY_CTX_set1_pbe_pass(pctx, password, password_len);
    EVP_PKEY_CTX_set1_argon2_salt(pctx, salt, salt_len);
    EVP_PKEY_derive(pctx, key, &key_len);

    EVP_PKEY_CTX_free(pctx);
    return 0;
}

// MAC Functions
int hmac_sha256_mac(const unsigned char *key, size_t key_len,
                    const unsigned char *data, size_t data_len,
                    unsigned char *mac, unsigned int *mac_len) {
    HMAC(EVP_sha256(), key, key_len, data, data_len, mac, mac_len);
    return 0;
}

int hmac_sha512_mac(const unsigned char *key, size_t key_len,
                    const unsigned char *data, size_t data_len,
                    unsigned char *mac, unsigned int *mac_len) {
    HMAC(EVP_sha512(), key, key_len, data, data_len, mac, mac_len);
    return 0;
}

int poly1305_mac(const unsigned char *key,
                 const unsigned char *data, size_t data_len,
                 unsigned char *mac) {
    EVP_MAC *evp_mac = EVP_MAC_fetch(NULL, "POLY1305", NULL);
    EVP_MAC_CTX *ctx = EVP_MAC_CTX_new(evp_mac);
    size_t mac_len = 16;

    EVP_MAC_init(ctx, key, 32, NULL);
    EVP_MAC_update(ctx, data, data_len);
    EVP_MAC_final(ctx, mac, &mac_len, 16);

    EVP_MAC_CTX_free(ctx);
    EVP_MAC_free(evp_mac);
    return 0;
}
