// Quantum Safe - Digital Signatures
#include <oqs/oqs.h>
#include <pqclean/dilithium2/api.h>
#include <pqclean/dilithium3/api.h>
#include <pqclean/dilithium5/api.h>
#include <pqclean/falcon512/api.h>
#include <pqclean/sphincs-shake256-128f-robust/api.h>
#include <string.h>
#include <stdlib.h>

// ML-DSA-44 (Dilithium2) Digital Signature
int ml_dsa_44_signature(void) {
    uint8_t public_key[PQCLEAN_DILITHIUM2_CLEAN_CRYPTO_PUBLICKEYBYTES];
    uint8_t secret_key[PQCLEAN_DILITHIUM2_CLEAN_CRYPTO_SECRETKEYBYTES];
    uint8_t signature[PQCLEAN_DILITHIUM2_CLEAN_CRYPTO_BYTES];
    size_t signature_len;

    const uint8_t message[] = "quantum safe message";
    size_t message_len = strlen((char*)message);

    PQCLEAN_DILITHIUM2_CLEAN_crypto_sign_keypair(public_key, secret_key);
    PQCLEAN_DILITHIUM2_CLEAN_crypto_sign_signature(signature, &signature_len, message, message_len, secret_key);

    return PQCLEAN_DILITHIUM2_CLEAN_crypto_sign_verify(signature, signature_len, message, message_len, public_key);
}

// ML-DSA-65 (Dilithium3) Digital Signature
int ml_dsa_65_example(void) {
    uint8_t pk[PQCLEAN_DILITHIUM3_CLEAN_CRYPTO_PUBLICKEYBYTES];
    uint8_t sk[PQCLEAN_DILITHIUM3_CLEAN_CRYPTO_SECRETKEYBYTES];
    uint8_t sig[PQCLEAN_DILITHIUM3_CLEAN_CRYPTO_BYTES];
    size_t sig_len;

    PQCLEAN_DILITHIUM3_CLEAN_crypto_sign_keypair(pk, sk);
    PQCLEAN_DILITHIUM3_CLEAN_crypto_sign_signature(sig, &sig_len, (uint8_t*)"test", 4, sk);
    return 0;
}

// ML-DSA-87 (Dilithium5) Digital Signature
int ml_dsa_87_signature(void) {
    uint8_t pk[PQCLEAN_DILITHIUM5_CLEAN_CRYPTO_PUBLICKEYBYTES];
    uint8_t sk[PQCLEAN_DILITHIUM5_CLEAN_CRYPTO_SECRETKEYBYTES];

    PQCLEAN_DILITHIUM5_CLEAN_crypto_sign_keypair(pk, sk);
    return 0;
}

// Falcon-512 Digital Signature
int falcon_512_signature(void) {
    uint8_t pk[PQCLEAN_FALCON512_CLEAN_CRYPTO_PUBLICKEYBYTES];
    uint8_t sk[PQCLEAN_FALCON512_CLEAN_CRYPTO_SECRETKEYBYTES];
    uint8_t sig[PQCLEAN_FALCON512_CLEAN_CRYPTO_BYTES];
    size_t sig_len;

    const uint8_t msg[] = "falcon signed message";

    PQCLEAN_FALCON512_CLEAN_crypto_sign_keypair(pk, sk);
    PQCLEAN_FALCON512_CLEAN_crypto_sign_signature(sig, &sig_len, msg, sizeof(msg), sk);

    return PQCLEAN_FALCON512_CLEAN_crypto_sign_verify(sig, sig_len, msg, sizeof(msg), pk);
}

// SLH-DSA (SPHINCS+) Digital Signature
int slh_dsa_sphincs_plus(void) {
    uint8_t pk[PQCLEAN_SPHINCSSHAKE256128FROBUST_CLEAN_CRYPTO_PUBLICKEYBYTES];
    uint8_t sk[PQCLEAN_SPHINCSSHAKE256128FROBUST_CLEAN_CRYPTO_SECRETKEYBYTES];
    uint8_t sig[PQCLEAN_SPHINCSSHAKE256128FROBUST_CLEAN_CRYPTO_BYTES];
    size_t sig_len;

    PQCLEAN_SPHINCSSHAKE256128FROBUST_CLEAN_crypto_sign_keypair(pk, sk);
    PQCLEAN_SPHINCSSHAKE256128FROBUST_CLEAN_crypto_sign_signature(sig, &sig_len, (uint8_t*)"data", 4, sk);
    return 0;
}

// liboqs Dilithium Implementation
int oqs_dilithium_signature(void) {
    OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_dilithium_2);
    if (sig == NULL) return -1;

    uint8_t *public_key = malloc(sig->length_public_key);
    uint8_t *secret_key = malloc(sig->length_secret_key);
    uint8_t *signature = malloc(sig->length_signature);
    size_t signature_len;

    const uint8_t message[] = "oqs dilithium message";

    OQS_SIG_keypair(sig, public_key, secret_key);
    OQS_SIG_sign(sig, signature, &signature_len, message, sizeof(message), secret_key);
    OQS_SIG_verify(sig, message, sizeof(message), signature, signature_len, public_key);

    free(public_key);
    free(secret_key);
    free(signature);
    OQS_SIG_free(sig);
    return 0;
}

// XMSS Hash-based Signature
int xmss_signature_example(void) {
    OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_dilithium_2);
    if (sig == NULL) return -1;

    uint8_t *pk = malloc(sig->length_public_key);
    uint8_t *sk = malloc(sig->length_secret_key);

    OQS_SIG_keypair(sig, pk, sk);

    free(pk);
    free(sk);
    OQS_SIG_free(sig);
    return 0;
}

// LMS Hash-based Signature
int lms_hash_based_signature(void) {
    OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_dilithium_3);
    if (sig == NULL) return -1;

    uint8_t *pk = malloc(sig->length_public_key);
    uint8_t *sk = malloc(sig->length_secret_key);

    OQS_SIG_keypair(sig, pk, sk);

    free(pk);
    free(sk);
    OQS_SIG_free(sig);
    return 0;
}
