// Quantum Resistant - Strong Symmetric Encryption and Hashes
const crypto = require('crypto');
const { sha3_256, sha3_384, sha3_512, shake128, shake256 } = require('@noble/hashes/sha3');
const { blake2b } = require('@noble/hashes/blake2b');
const { blake3 } = require('@noble/hashes/blake3');
const { chacha20poly1305 } = require('@noble/ciphers/chacha');

// Strong Symmetric (256-bit)
function aes256GcmEncryption(plaintext, key) {
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
    let encrypted = cipher.update(plaintext, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    const authTag = cipher.getAuthTag();
    return { encrypted, iv, authTag };
}

function chacha20Poly1305Encryption(plaintext, key, nonce) {
    const cipher = chacha20poly1305(key, nonce);
    const ciphertext = cipher.encrypt(plaintext);
    return ciphertext;
}

// Strong Symmetric (192-bit)
function aes192Encryption(plaintext, key) {
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-192-cbc', key, iv);
    let encrypted = cipher.update(plaintext, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    return { encrypted, iv };
}

// Strong Hash (512-bit)
function sha512Hash(data) {
    return crypto.createHash('sha512').update(data).digest('hex');
}

function sha3_512Hash(data) {
    return sha3_512(data);
}

// Strong Hash (384-bit)
function sha384Hash(data) {
    return crypto.createHash('sha384').update(data).digest('hex');
}

function sha3_384Hash(data) {
    return sha3_384(data);
}

// Strong Hash (256-bit)
function sha256Hash(data) {
    return crypto.createHash('sha256').update(data).digest('hex');
}

function sha3_256Hash(data) {
    return sha3_256(data);
}

function blake3Hash(data) {
    return blake3(data);
}

// Strong Hash (Variable)
function shake128Xof(data, length = 32) {
    return shake128(data, { dkLen: length });
}

function shake256Xof(data, length = 64) {
    return shake256(data, { dkLen: length });
}

function blake2bHash(data) {
    return blake2b(data);
}

module.exports = {
    aes256GcmEncryption,
    chacha20Poly1305Encryption,
    aes192Encryption,
    sha512Hash,
    sha3_512Hash,
    sha384Hash,
    sha3_384Hash,
    sha256Hash,
    sha3_256Hash,
    blake3Hash,
    shake128Xof,
    shake256Xof,
    blake2bHash
};
