// Quantum Resistant - KDF and MAC
use hkdf::Hkdf;
use sha2::Sha256;
use pbkdf2::pbkdf2_hmac;
use argon2::{Argon2, PasswordHasher};
use scrypt::{scrypt, Params as ScryptParams};
use hmac::{Hmac, Mac};

type HmacSha256 = Hmac<Sha256>;
type HmacSha512 = Hmac<sha2::Sha512>;

// KDF Functions
fn hkdf_derive() {
    let hk = Hkdf::<Sha256>::new(Some(&salt), &ikm);
    let mut okm = [0u8; 32];
    hk.expand(&info, &mut okm).unwrap();
}

fn pbkdf2_derive() {
    let mut key = [0u8; 32];
    pbkdf2_hmac::<Sha256>(password, salt, 100_000, &mut key);
}

fn argon2_derive() {
    let argon2 = Argon2::default();
    let password_hash = argon2.hash_password(password, &salt).unwrap();
}

fn scrypt_derive() {
    let params = ScryptParams::new(15, 8, 1).unwrap();
    let mut output = [0u8; 32];
    scrypt(password, salt, &params, &mut output).unwrap();
}

fn bcrypt_hash() {
    use bcrypt::{hash, verify, DEFAULT_COST};
    let hashed = hash(password, DEFAULT_COST).unwrap();
    let valid = verify(password, &hashed).unwrap();
}

// MAC Functions
fn hmac_sha256_mac() {
    let mut mac = HmacSha256::new_from_slice(key).unwrap();
    mac.update(message);
    let result = mac.finalize();
}

fn hmac_sha512_mac() {
    let mut mac = HmacSha512::new_from_slice(key).unwrap();
    mac.update(message);
    let tag = mac.finalize().into_bytes();
}

fn poly1305_mac() {
    use poly1305::Poly1305;
    let mac = Poly1305::new(key.into());
    let tag = mac.compute_unpadded(message);
}
