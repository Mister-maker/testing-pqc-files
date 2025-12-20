// Quantum Safe - Key Encapsulation Mechanisms (KEM)
#include <oqs/oqs.h>
#include <pqclean/kyber768/api.h>
#include <pqclean/kyber1024/api.h>
#include <pqclean/kyber512/api.h>
#include <pqclean/frodokem640shake/api.h>
#include <string.h>
#include <stdlib.h>

// ML-KEM-768 (Kyber768) Key Encapsulation
int ml_kem_768_encapsulation(void) {
    uint8_t public_key[PQCLEAN_KYBER768_CLEAN_CRYPTO_PUBLICKEYBYTES];
    uint8_t secret_key[PQCLEAN_KYBER768_CLEAN_CRYPTO_SECRETKEYBYTES];
    uint8_t ciphertext[PQCLEAN_KYBER768_CLEAN_CRYPTO_CIPHERTEXTBYTES];
    uint8_t shared_secret_enc[PQCLEAN_KYBER768_CLEAN_CRYPTO_BYTES];
    uint8_t shared_secret_dec[PQCLEAN_KYBER768_CLEAN_CRYPTO_BYTES];

    PQCLEAN_KYBER768_CLEAN_crypto_kem_keypair(public_key, secret_key);
    PQCLEAN_KYBER768_CLEAN_crypto_kem_enc(ciphertext, shared_secret_enc, public_key);
    PQCLEAN_KYBER768_CLEAN_crypto_kem_dec(shared_secret_dec, ciphertext, secret_key);

    return memcmp(shared_secret_enc, shared_secret_dec, PQCLEAN_KYBER768_CLEAN_CRYPTO_BYTES) == 0;
}

// ML-KEM-1024 (Kyber1024) Key Encapsulation
int ml_kem_1024_example(void) {
    uint8_t pk[PQCLEAN_KYBER1024_CLEAN_CRYPTO_PUBLICKEYBYTES];
    uint8_t sk[PQCLEAN_KYBER1024_CLEAN_CRYPTO_SECRETKEYBYTES];
    uint8_t ct[PQCLEAN_KYBER1024_CLEAN_CRYPTO_CIPHERTEXTBYTES];
    uint8_t ss[PQCLEAN_KYBER1024_CLEAN_CRYPTO_BYTES];

    PQCLEAN_KYBER1024_CLEAN_crypto_kem_keypair(pk, sk);
    PQCLEAN_KYBER1024_CLEAN_crypto_kem_enc(ct, ss, pk);
    return 0;
}

// ML-KEM-512 (Kyber512) Key Encapsulation
int ml_kem_512_example(void) {
    uint8_t pk[PQCLEAN_KYBER512_CLEAN_CRYPTO_PUBLICKEYBYTES];
    uint8_t sk[PQCLEAN_KYBER512_CLEAN_CRYPTO_SECRETKEYBYTES];

    PQCLEAN_KYBER512_CLEAN_crypto_kem_keypair(pk, sk);
    return 0;
}

// FrodoKEM Key Encapsulation
int frodokem_example(void) {
    uint8_t pk[PQCLEAN_FRODOKEM640SHAKE_CLEAN_CRYPTO_PUBLICKEYBYTES];
    uint8_t sk[PQCLEAN_FRODOKEM640SHAKE_CLEAN_CRYPTO_SECRETKEYBYTES];
    uint8_t ct[PQCLEAN_FRODOKEM640SHAKE_CLEAN_CRYPTO_CIPHERTEXTBYTES];
    uint8_t ss[PQCLEAN_FRODOKEM640SHAKE_CLEAN_CRYPTO_BYTES];

    PQCLEAN_FRODOKEM640SHAKE_CLEAN_crypto_kem_keypair(pk, sk);
    PQCLEAN_FRODOKEM640SHAKE_CLEAN_crypto_kem_enc(ct, ss, pk);
    return 0;
}

// liboqs Kyber768 Implementation
int oqs_kyber_768(void) {
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_kyber_768);
    if (kem == NULL) return -1;

    uint8_t *public_key = malloc(kem->length_public_key);
    uint8_t *secret_key = malloc(kem->length_secret_key);
    uint8_t *ciphertext = malloc(kem->length_ciphertext);
    uint8_t *shared_secret = malloc(kem->length_shared_secret);

    OQS_KEM_keypair(kem, public_key, secret_key);
    OQS_KEM_encaps(kem, ciphertext, shared_secret, public_key);
    OQS_KEM_decaps(kem, shared_secret, ciphertext, secret_key);

    free(public_key);
    free(secret_key);
    free(ciphertext);
    free(shared_secret);
    OQS_KEM_free(kem);
    return 0;
}

// Kyber Key Generation
int kyber_key_generation(void) {
    uint8_t pk[PQCLEAN_KYBER768_CLEAN_CRYPTO_PUBLICKEYBYTES];
    uint8_t sk[PQCLEAN_KYBER768_CLEAN_CRYPTO_SECRETKEYBYTES];

    return PQCLEAN_KYBER768_CLEAN_crypto_kem_keypair(pk, sk);
}
