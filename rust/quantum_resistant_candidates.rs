// Quantum Resistant - PQC Candidates (KEM and Signatures)
use pqcrypto_ntru::ntruhps2048509;
use pqcrypto_classicmceliece::mceliece348864;
use pqcrypto_hqc::hqc128;
use pqcrypto_bike::bike1l1cpa;

// PQC Candidate KEMs
fn ntru_kem_example() {
    let (pk, sk) = ntruhps2048509::keypair();
    let (ss, ct) = ntruhps2048509::encapsulate(&pk);
    let decrypted = ntruhps2048509::decapsulate(&ct, &sk);
}

fn classic_mceliece_kem() {
    let (pk, sk) = mceliece348864::keypair();
    let (shared_secret, ciphertext) = mceliece348864::encapsulate(&pk);
}

fn hqc_kem_example() {
    let (pk, sk) = hqc128::keypair();
    let (ss, ct) = hqc128::encapsulate(&pk);
}

fn bike_kem_example() {
    let (pk, sk) = bike1l1cpa::keypair();
    let (ss, ct) = bike1l1cpa::encapsulate(&pk);
}

fn sike_vulnerable_kem() {
    // SIKE - Supersingular Isogeny Key Encapsulation (VULNERABLE - broken)
    let sike_params = SikeParams::p434();
    let (pk, sk) = sike_keygen(&sike_params);
}

// PQC Candidate Signatures
fn picnic_signature() {
    use pqcrypto_picnic::picnicl1full;
    let (pk, sk) = picnicl1full::keypair();
    let sig = picnicl1full::sign(b"picnic message", &sk);
}

fn rainbow_vulnerable_signature() {
    // Rainbow signature scheme (VULNERABLE - broken)
    use pqcrypto_rainbow::rainbowiaclassic;
    let (pk, sk) = rainbowiaclassic::keypair();
}

fn gemss_signature_example() {
    // GeMSS - Great Multivariate Signature Scheme
    let gemss_keypair = gemss_keygen(GemssParams::GeMSS128);
}
