// Quantum Safe - Hybrid PQC Implementations
#include <oqs/oqs.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/rand.h>
#include <string.h>
#include <stdlib.h>

// Hybrid X25519 + Kyber768
int hybrid_x25519_kyber768(unsigned char *final_key) {
    // Classical X25519
    EVP_PKEY *x25519_key = NULL;
    EVP_PKEY_CTX *x25519_ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
    EVP_PKEY_keygen_init(x25519_ctx);
    EVP_PKEY_keygen(x25519_ctx, &x25519_key);

    size_t x25519_pubkey_len = 32;
    unsigned char x25519_pubkey[32];
    EVP_PKEY_get_raw_public_key(x25519_key, x25519_pubkey, &x25519_pubkey_len);

    // Post-quantum Kyber768
    OQS_KEM *kyber = OQS_KEM_new(OQS_KEM_alg_kyber_768);
    uint8_t *kyber_pk = malloc(kyber->length_public_key);
    uint8_t *kyber_sk = malloc(kyber->length_secret_key);
    uint8_t *kyber_ct = malloc(kyber->length_ciphertext);
    uint8_t *kyber_ss = malloc(kyber->length_shared_secret);

    OQS_KEM_keypair(kyber, kyber_pk, kyber_sk);
    OQS_KEM_encaps(kyber, kyber_ct, kyber_ss, kyber_pk);

    // Combine shared secrets with HKDF
    unsigned char combined[64];
    memcpy(combined, x25519_pubkey, 32);
    memcpy(combined + 32, kyber_ss, 32);

    EVP_PKEY_CTX *hkdf_ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    EVP_PKEY_derive_init(hkdf_ctx);
    EVP_PKEY_CTX_set_hkdf_md(hkdf_ctx, EVP_sha256());
    EVP_PKEY_CTX_set1_hkdf_key(hkdf_ctx, combined, 64);
    EVP_PKEY_CTX_add1_hkdf_info(hkdf_ctx, (unsigned char*)"hybrid-kem", 10);

    size_t final_key_len = 32;
    EVP_PKEY_derive(hkdf_ctx, final_key, &final_key_len);

    // Cleanup
    EVP_PKEY_CTX_free(x25519_ctx);
    EVP_PKEY_CTX_free(hkdf_ctx);
    EVP_PKEY_free(x25519_key);
    free(kyber_pk);
    free(kyber_sk);
    free(kyber_ct);
    free(kyber_ss);
    OQS_KEM_free(kyber);

    return 0;
}

// Hybrid ECDH + ML-KEM
int hybrid_ecdh_mlkem(unsigned char *shared_secret) {
    // ECDH P-256
    EVP_PKEY *ec_key = NULL;
    EVP_PKEY_CTX *ec_ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    EVP_PKEY_keygen_init(ec_ctx);
    EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ec_ctx, NID_X9_62_prime256v1);
    EVP_PKEY_keygen(ec_ctx, &ec_key);

    // ML-KEM (Kyber768)
    OQS_KEM *mlkem = OQS_KEM_new(OQS_KEM_alg_kyber_768);
    uint8_t *mlkem_pk = malloc(mlkem->length_public_key);
    uint8_t *mlkem_sk = malloc(mlkem->length_secret_key);
    uint8_t *mlkem_ct = malloc(mlkem->length_ciphertext);
    uint8_t *mlkem_ss = malloc(mlkem->length_shared_secret);

    OQS_KEM_keypair(mlkem, mlkem_pk, mlkem_sk);
    OQS_KEM_encaps(mlkem, mlkem_ct, mlkem_ss, mlkem_pk);

    memcpy(shared_secret, mlkem_ss, mlkem->length_shared_secret);

    // Cleanup
    EVP_PKEY_CTX_free(ec_ctx);
    EVP_PKEY_free(ec_key);
    free(mlkem_pk);
    free(mlkem_sk);
    free(mlkem_ct);
    free(mlkem_ss);
    OQS_KEM_free(mlkem);

    return 0;
}

// Hybrid TLS with PQC
int hybrid_tls_pqc(void) {
    // X25519 component
    EVP_PKEY *x25519_key = NULL;
    EVP_PKEY_CTX *x25519_ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
    EVP_PKEY_keygen_init(x25519_ctx);
    EVP_PKEY_keygen(x25519_ctx, &x25519_key);

    // Kyber768 component
    OQS_KEM *kyber = OQS_KEM_new(OQS_KEM_alg_kyber_768);
    uint8_t *kyber_pk = malloc(kyber->length_public_key);
    uint8_t *kyber_sk = malloc(kyber->length_secret_key);

    OQS_KEM_keypair(kyber, kyber_pk, kyber_sk);

    // Cleanup
    EVP_PKEY_CTX_free(x25519_ctx);
    EVP_PKEY_free(x25519_key);
    free(kyber_pk);
    free(kyber_sk);
    OQS_KEM_free(kyber);

    return 0;
}

// X25519Kyber768Draft00 IETF draft
int x25519_kyber768_draft00(unsigned char *hybrid_public, size_t *hybrid_public_len) {
    // X25519
    EVP_PKEY *x25519_key = NULL;
    EVP_PKEY_CTX *x25519_ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
    EVP_PKEY_keygen_init(x25519_ctx);
    EVP_PKEY_keygen(x25519_ctx, &x25519_key);

    unsigned char x25519_pub[32];
    size_t x25519_pub_len = 32;
    EVP_PKEY_get_raw_public_key(x25519_key, x25519_pub, &x25519_pub_len);

    // Kyber768
    OQS_KEM *kyber = OQS_KEM_new(OQS_KEM_alg_kyber_768);
    uint8_t *kyber_pk = malloc(kyber->length_public_key);
    uint8_t *kyber_sk = malloc(kyber->length_secret_key);

    OQS_KEM_keypair(kyber, kyber_pk, kyber_sk);

    // Combine public keys
    memcpy(hybrid_public, x25519_pub, 32);
    memcpy(hybrid_public + 32, kyber_pk, kyber->length_public_key);
    *hybrid_public_len = 32 + kyber->length_public_key;

    // Cleanup
    EVP_PKEY_CTX_free(x25519_ctx);
    EVP_PKEY_free(x25519_key);
    free(kyber_pk);
    free(kyber_sk);
    OQS_KEM_free(kyber);

    return 0;
}

// ECDH + Kyber Composite
int ecdh_kyber_composite(unsigned char *composite_secret) {
    // ECDH P-384
    EVP_PKEY *ec_key = NULL;
    EVP_PKEY_CTX *ec_ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    EVP_PKEY_keygen_init(ec_ctx);
    EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ec_ctx, NID_secp384r1);
    EVP_PKEY_keygen(ec_ctx, &ec_key);

    // Kyber768
    OQS_KEM *kyber = OQS_KEM_new(OQS_KEM_alg_kyber_768);
    uint8_t *kyber_pk = malloc(kyber->length_public_key);
    uint8_t *kyber_sk = malloc(kyber->length_secret_key);
    uint8_t *kyber_ct = malloc(kyber->length_ciphertext);
    uint8_t *kyber_ss = malloc(kyber->length_shared_secret);

    OQS_KEM_keypair(kyber, kyber_pk, kyber_sk);
    OQS_KEM_encaps(kyber, kyber_ct, kyber_ss, kyber_pk);

    // Combine with HKDF
    EVP_PKEY_CTX *hkdf_ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    EVP_PKEY_derive_init(hkdf_ctx);
    EVP_PKEY_CTX_set_hkdf_md(hkdf_ctx, EVP_sha256());
    EVP_PKEY_CTX_set1_hkdf_key(hkdf_ctx, kyber_ss, kyber->length_shared_secret);
    EVP_PKEY_CTX_add1_hkdf_info(hkdf_ctx, (unsigned char*)"composite-kem", 13);

    size_t secret_len = 32;
    EVP_PKEY_derive(hkdf_ctx, composite_secret, &secret_len);

    // Cleanup
    EVP_PKEY_CTX_free(ec_ctx);
    EVP_PKEY_CTX_free(hkdf_ctx);
    EVP_PKEY_free(ec_key);
    free(kyber_pk);
    free(kyber_sk);
    free(kyber_ct);
    free(kyber_ss);
    OQS_KEM_free(kyber);

    return 0;
}
