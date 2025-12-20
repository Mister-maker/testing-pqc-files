// Quantum Resistant - PQC Candidates (KEM and Signatures)
#include <oqs/oqs.h>
#include <stdlib.h>
#include <string.h>

// PQC Candidate KEMs

// NTRU Key Encapsulation
int ntru_kem_example(void) {
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_ntru_hps2048509);
    if (kem == NULL) return -1;

    uint8_t *pk = malloc(kem->length_public_key);
    uint8_t *sk = malloc(kem->length_secret_key);
    uint8_t *ct = malloc(kem->length_ciphertext);
    uint8_t *ss = malloc(kem->length_shared_secret);

    OQS_KEM_keypair(kem, pk, sk);
    OQS_KEM_encaps(kem, ct, ss, pk);
    OQS_KEM_decaps(kem, ss, ct, sk);

    free(pk); free(sk); free(ct); free(ss);
    OQS_KEM_free(kem);
    return 0;
}

// Classic McEliece Key Encapsulation
int classic_mceliece_kem(void) {
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_classic_mceliece_348864);
    if (kem == NULL) return -1;

    uint8_t *public_key = malloc(kem->length_public_key);
    uint8_t *secret_key = malloc(kem->length_secret_key);
    uint8_t *ciphertext = malloc(kem->length_ciphertext);
    uint8_t *shared_secret = malloc(kem->length_shared_secret);

    OQS_KEM_keypair(kem, public_key, secret_key);
    OQS_KEM_encaps(kem, ciphertext, shared_secret, public_key);

    free(public_key); free(secret_key); free(ciphertext); free(shared_secret);
    OQS_KEM_free(kem);
    return 0;
}

// HQC Key Encapsulation
int hqc_kem_example(void) {
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_hqc_128);
    if (kem == NULL) return -1;

    uint8_t *pk = malloc(kem->length_public_key);
    uint8_t *sk = malloc(kem->length_secret_key);
    uint8_t *ct = malloc(kem->length_ciphertext);
    uint8_t *ss = malloc(kem->length_shared_secret);

    OQS_KEM_keypair(kem, pk, sk);
    OQS_KEM_encaps(kem, ct, ss, pk);

    free(pk); free(sk); free(ct); free(ss);
    OQS_KEM_free(kem);
    return 0;
}

// BIKE Key Encapsulation
int bike_kem_example(void) {
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_bike_l1);
    if (kem == NULL) return -1;

    uint8_t *pk = malloc(kem->length_public_key);
    uint8_t *sk = malloc(kem->length_secret_key);
    uint8_t *ct = malloc(kem->length_ciphertext);
    uint8_t *ss = malloc(kem->length_shared_secret);

    OQS_KEM_keypair(kem, pk, sk);
    OQS_KEM_encaps(kem, ct, ss, pk);

    free(pk); free(sk); free(ct); free(ss);
    OQS_KEM_free(kem);
    return 0;
}

// SIKE - VULNERABLE (broken)
int sike_vulnerable_kem(void) {
    // SIKE has been broken and should not be used
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_sike_p434);
    if (kem == NULL) return -1;

    uint8_t *pk = malloc(kem->length_public_key);
    uint8_t *sk = malloc(kem->length_secret_key);

    OQS_KEM_keypair(kem, pk, sk);

    free(pk); free(sk);
    OQS_KEM_free(kem);
    return 0;
}

// PQC Candidate Signatures

// Picnic Signature
int picnic_signature(void) {
    OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_picnic_L1_full);
    if (sig == NULL) return -1;

    uint8_t *pk = malloc(sig->length_public_key);
    uint8_t *sk = malloc(sig->length_secret_key);
    uint8_t *signature = malloc(sig->length_signature);
    size_t sig_len;

    OQS_SIG_keypair(sig, pk, sk);
    OQS_SIG_sign(sig, signature, &sig_len, (uint8_t*)"picnic", 6, sk);

    free(pk); free(sk); free(signature);
    OQS_SIG_free(sig);
    return 0;
}

// Rainbow - VULNERABLE (broken)
int rainbow_vulnerable_signature(void) {
    // Rainbow has been broken and should not be used
    OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_rainbow_I_classic);
    if (sig == NULL) return -1;

    uint8_t *pk = malloc(sig->length_public_key);
    uint8_t *sk = malloc(sig->length_secret_key);

    OQS_SIG_keypair(sig, pk, sk);

    free(pk); free(sk);
    OQS_SIG_free(sig);
    return 0;
}

// GeMSS Signature
int gemss_signature_example(void) {
    OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_dilithium_2);
    if (sig == NULL) return -1;

    uint8_t *pk = malloc(sig->length_public_key);
    uint8_t *sk = malloc(sig->length_secret_key);

    OQS_SIG_keypair(sig, pk, sk);

    free(pk); free(sk);
    OQS_SIG_free(sig);
    return 0;
}
