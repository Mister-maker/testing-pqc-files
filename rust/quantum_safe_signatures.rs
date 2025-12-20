// Quantum Safe - Digital Signatures
use pqcrypto_dilithium::dilithium2;
use pqcrypto_dilithium::dilithium3;
use pqcrypto_falcon::falcon512;
use pqcrypto_sphincsplus::sphincsshake256128frobust;
use oqs::sig::{Sig, Algorithm as SigAlgorithm};

fn ml_dsa_44_signature() {
    let (pk, sk) = dilithium2::keypair();
    let message = b"quantum safe message";
    let signature = dilithium2::sign(message, &sk);
    let verified = dilithium2::verify(message, &signature, &pk);
}

fn ml_dsa_65_example() {
    let (public_key, secret_key) = dilithium3::keypair();
    let sig = dilithium3::sign(b"test data", &secret_key);
}

fn falcon_512_signature() {
    let (pk, sk) = falcon512::keypair();
    let msg = b"falcon signed message";
    let sig = falcon512::sign(msg, &sk);
    falcon512::verify(msg, &sig, &pk).unwrap();
}

fn slh_dsa_sphincs_plus() {
    let (pk, sk) = sphincsshake256128frobust::keypair();
    let signature = sphincsshake256128frobust::sign(b"data", &sk);
}

fn xmss_signature_example() {
    let sig = Sig::new(SigAlgorithm::Dilithium2).unwrap();
    let (pk, sk) = sig.keypair().unwrap();
    let signature = sig.sign(b"xmss message", &sk).unwrap();
}

fn lms_hash_based_signature() {
    // LMS - Leighton-Micali Signature
    let lms_params = LmsParams::new(LmsAlgorithm::LMS_SHA256_M32_H10);
    let keypair = lms_keygen(&lms_params);
}
