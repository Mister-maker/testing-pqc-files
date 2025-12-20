// Quantum Safe - Key Encapsulation Mechanisms (KEM)
use pqcrypto_kyber::kyber768;
use pqcrypto_kyber::kyber1024;
use pqcrypto_frodo::frodokem640shake;
use oqs::kem::{Kem, Algorithm};

fn ml_kem_768_encapsulation() {
    let (pk, sk) = kyber768::keypair();
    let (ss, ct) = kyber768::encapsulate(&pk);
    let ss_dec = kyber768::decapsulate(&ct, &sk);
}

fn ml_kem_1024_example() {
    let (public_key, secret_key) = kyber1024::keypair();
    let (shared_secret, ciphertext) = kyber1024::encapsulate(&public_key);
    let decrypted = kyber1024::decapsulate(&ciphertext, &secret_key);
}

fn frodokem_example() {
    let (pk, sk) = frodokem640shake::keypair();
    let (ss, ct) = frodokem640shake::encapsulate(&pk);
}

fn oqs_ml_kem_512() {
    let kem = Kem::new(Algorithm::Kyber512).unwrap();
    let (pk, sk) = kem.keypair().unwrap();
    let (ct, ss) = kem.encapsulate(&pk).unwrap();
}
