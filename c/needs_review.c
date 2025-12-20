// Needs Review - Generic Terms, Ambiguous AES, Library References
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <string.h>
#include <stdlib.h>

// Generic Terms (Need context to determine security)
int encrypt(const unsigned char *plaintext, int plaintext_len,
            const unsigned char *key, unsigned char *ciphertext) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    unsigned char iv[16];
    int len, ciphertext_len;

    RAND_bytes(iv, 16);
    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);
    EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len);
    ciphertext_len = len;
    EVP_EncryptFinal_ex(ctx, ciphertext + len, &len);

    EVP_CIPHER_CTX_free(ctx);
    return ciphertext_len + len;
}

int decrypt(const unsigned char *ciphertext, int ciphertext_len,
            const unsigned char *key, const unsigned char *iv,
            unsigned char *plaintext) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len, plaintext_len;

    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);
    EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len);
    plaintext_len = len;
    EVP_DecryptFinal_ex(ctx, plaintext + len, &len);

    EVP_CIPHER_CTX_free(ctx);
    return plaintext_len + len;
}

int sign(const unsigned char *message, size_t message_len,
         EVP_PKEY *private_key, unsigned char *signature, size_t *sig_len) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestSignInit(ctx, NULL, EVP_sha256(), NULL, private_key);
    EVP_DigestSignUpdate(ctx, message, message_len);
    EVP_DigestSignFinal(ctx, signature, sig_len);
    EVP_MD_CTX_free(ctx);
    return 0;
}

int verify(const unsigned char *message, size_t message_len,
           const unsigned char *signature, size_t sig_len,
           EVP_PKEY *public_key) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestVerifyInit(ctx, NULL, EVP_sha256(), NULL, public_key);
    EVP_DigestVerifyUpdate(ctx, message, message_len);
    int result = EVP_DigestVerifyFinal(ctx, signature, sig_len);
    EVP_MD_CTX_free(ctx);
    return result;
}

void hash(const unsigned char *data, size_t len, unsigned char *digest) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(ctx, data, len);
    EVP_DigestFinal_ex(ctx, digest, NULL);
    EVP_MD_CTX_free(ctx);
}

unsigned char* generate_key(size_t length) {
    unsigned char *key = malloc(length);
    RAND_bytes(key, length);
    return key;
}

EVP_CIPHER_CTX* create_cipher(const unsigned char *key) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    unsigned char iv[16];
    RAND_bytes(iv, 16);
    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);
    return ctx;
}

// Ambiguous AES (key size not specified)
int aes_encrypt(const unsigned char *plaintext, int plaintext_len,
                const unsigned char *key, unsigned char *ciphertext) {
    // AES without explicit key size - could be 128, 192, or 256
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    unsigned char iv[16];
    int len;

    RAND_bytes(iv, 16);
    EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv);
    EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len);

    EVP_CIPHER_CTX_free(ctx);
    return len;
}

int aes_decrypt(const unsigned char *ciphertext, int ciphertext_len,
                const unsigned char *key, const unsigned char *iv,
                unsigned char *plaintext) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len;

    EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv);
    EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len);

    EVP_CIPHER_CTX_free(ctx);
    return len;
}

int aes_cbc_mode(const unsigned char *data, int data_len,
                 const unsigned char *key, const unsigned char *iv,
                 unsigned char *output) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len;

    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);
    EVP_EncryptUpdate(ctx, output, &len, data, data_len);

    EVP_CIPHER_CTX_free(ctx);
    return len;
}

int aes_ecb_mode(const unsigned char *data, int data_len,
                 const unsigned char *key, unsigned char *output) {
    // ECB mode is insecure - avoid using
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len;

    EVP_EncryptInit_ex(ctx, EVP_aes_256_ecb(), NULL, key, NULL);
    EVP_EncryptUpdate(ctx, output, &len, data, data_len);

    EVP_CIPHER_CTX_free(ctx);
    return len;
}

// Library References
void use_openssl(void) {
    // OpenSSL library usage
    OpenSSL_add_all_algorithms();
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX_free(ctx);
}

void use_libsodium(void) {
    // libsodium usage would be:
    // sodium_init();
    // crypto_secretbox_easy(...);
    // crypto_box_easy(...);
}

void use_mbedtls(void) {
    // mbedTLS usage would be:
    // mbedtls_aes_context aes;
    // mbedtls_aes_init(&aes);
    // mbedtls_aes_setkey_enc(&aes, key, 256);
}
