// Quantum Resistant - Strong Symmetric Encryption and Hashes
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <string.h>
#include <stdlib.h>

// Strong Symmetric (256-bit)
int aes_256_gcm_encryption(const unsigned char *plaintext, int plaintext_len,
                           const unsigned char *key, unsigned char *ciphertext) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    unsigned char iv[12];
    unsigned char tag[16];
    int len, ciphertext_len;

    RAND_bytes(iv, 12);
    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, iv);
    EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len);
    ciphertext_len = len;
    EVP_EncryptFinal_ex(ctx, ciphertext + len, &len);
    ciphertext_len += len;
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag);

    EVP_CIPHER_CTX_free(ctx);
    return ciphertext_len;
}

int chacha20_poly1305_encryption(const unsigned char *plaintext, int plaintext_len,
                                  const unsigned char *key, unsigned char *ciphertext) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    unsigned char iv[12];
    int len, ciphertext_len;

    RAND_bytes(iv, 12);
    EVP_EncryptInit_ex(ctx, EVP_chacha20_poly1305(), NULL, key, iv);
    EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len);
    ciphertext_len = len;
    EVP_EncryptFinal_ex(ctx, ciphertext + len, &len);

    EVP_CIPHER_CTX_free(ctx);
    return ciphertext_len;
}

// Strong Symmetric (192-bit)
int aes_192_encryption(const unsigned char *plaintext, int plaintext_len,
                       const unsigned char *key, unsigned char *ciphertext) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    unsigned char iv[12];
    int len, ciphertext_len;

    RAND_bytes(iv, 12);
    EVP_EncryptInit_ex(ctx, EVP_aes_192_gcm(), NULL, key, iv);
    EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len);
    ciphertext_len = len;
    EVP_EncryptFinal_ex(ctx, ciphertext + len, &len);

    EVP_CIPHER_CTX_free(ctx);
    return ciphertext_len;
}

// Strong Hash (512-bit)
void sha512_hash(const unsigned char *data, size_t len, unsigned char *hash) {
    SHA512(data, len, hash);
}

void sha3_512_hash(const unsigned char *data, size_t len, unsigned char *hash) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha3_512(), NULL);
    EVP_DigestUpdate(ctx, data, len);
    EVP_DigestFinal_ex(ctx, hash, NULL);
    EVP_MD_CTX_free(ctx);
}

// Strong Hash (384-bit)
void sha384_hash(const unsigned char *data, size_t len, unsigned char *hash) {
    SHA384(data, len, hash);
}

void sha3_384_hash(const unsigned char *data, size_t len, unsigned char *hash) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha3_384(), NULL);
    EVP_DigestUpdate(ctx, data, len);
    EVP_DigestFinal_ex(ctx, hash, NULL);
    EVP_MD_CTX_free(ctx);
}

// Strong Hash (256-bit)
void sha256_hash(const unsigned char *data, size_t len, unsigned char *hash) {
    SHA256(data, len, hash);
}

void sha3_256_hash(const unsigned char *data, size_t len, unsigned char *hash) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha3_256(), NULL);
    EVP_DigestUpdate(ctx, data, len);
    EVP_DigestFinal_ex(ctx, hash, NULL);
    EVP_MD_CTX_free(ctx);
}

void blake2b_hash(const unsigned char *data, size_t len, unsigned char *hash) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_blake2b512(), NULL);
    EVP_DigestUpdate(ctx, data, len);
    EVP_DigestFinal_ex(ctx, hash, NULL);
    EVP_MD_CTX_free(ctx);
}

// Strong Hash (Variable - XOF)
void shake128_xof(const unsigned char *data, size_t len, unsigned char *output, size_t output_len) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_shake128(), NULL);
    EVP_DigestUpdate(ctx, data, len);
    EVP_DigestFinalXOF(ctx, output, output_len);
    EVP_MD_CTX_free(ctx);
}

void shake256_xof(const unsigned char *data, size_t len, unsigned char *output, size_t output_len) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_shake256(), NULL);
    EVP_DigestUpdate(ctx, data, len);
    EVP_DigestFinalXOF(ctx, output, output_len);
    EVP_MD_CTX_free(ctx);
}
