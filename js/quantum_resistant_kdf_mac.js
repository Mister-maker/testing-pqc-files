// Quantum Resistant - KDF and MAC
const crypto = require('crypto');
const { hkdf } = require('@noble/hashes/hkdf');
const { sha256 } = require('@noble/hashes/sha256');
const { pbkdf2 } = require('@noble/hashes/pbkdf2');
const argon2 = require('argon2');
const bcrypt = require('bcrypt');
const { poly1305 } = require('@noble/ciphers/chacha');

// KDF Functions
function hkdfDerive(ikm, salt, info, length = 32) {
    return hkdf(sha256, ikm, salt, info, length);
}

function hkdfNodeDerive(secret, salt, info, length = 32) {
    return crypto.hkdfSync('sha256', secret, salt, info, length);
}

function pbkdf2Derive(password, salt, iterations = 100000, keylen = 32) {
    return pbkdf2(sha256, password, salt, { c: iterations, dkLen: keylen });
}

function pbkdf2NodeDerive(password, salt, iterations = 100000, keylen = 32) {
    return crypto.pbkdf2Sync(password, salt, iterations, keylen, 'sha256');
}

async function argon2Derive(password, salt) {
    const hash = await argon2.hash(password, {
        type: argon2.argon2id,
        memoryCost: 65536,
        timeCost: 3,
        parallelism: 4,
        salt: salt
    });
    return hash;
}

async function argon2Verify(hash, password) {
    return await argon2.verify(hash, password);
}

function scryptDerive(password, salt, keylen = 32) {
    return crypto.scryptSync(password, salt, keylen, {
        N: 16384,
        r: 8,
        p: 1
    });
}

async function bcryptHash(password, rounds = 12) {
    const hash = await bcrypt.hash(password, rounds);
    return hash;
}

async function bcryptVerify(password, hash) {
    return await bcrypt.compare(password, hash);
}

// MAC Functions
function hmacSha256Mac(key, message) {
    return crypto.createHmac('sha256', key).update(message).digest();
}

function hmacSha512Mac(key, message) {
    return crypto.createHmac('sha512', key).update(message).digest();
}

function poly1305Mac(key, message) {
    return poly1305(key, message);
}

module.exports = {
    hkdfDerive,
    hkdfNodeDerive,
    pbkdf2Derive,
    pbkdf2NodeDerive,
    argon2Derive,
    argon2Verify,
    scryptDerive,
    bcryptHash,
    bcryptVerify,
    hmacSha256Mac,
    hmacSha512Mac,
    poly1305Mac
};
