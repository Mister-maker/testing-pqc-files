// Quantum Vulnerable - Broken/Weak Algorithms (DO NOT USE IN PRODUCTION)
const crypto = require('crypto');
const forge = require('node-forge');

// Broken Hash (VULNERABLE)
function md5BrokenHash(data) {
    return crypto.createHash('md5').update(data).digest('hex');
}

function md4BrokenHash(data) {
    return forge.md.md4.create().update(data).digest().toHex();
}

function sha1BrokenHash(data) {
    return crypto.createHash('sha1').update(data).digest('hex');
}

function ripemdWeakHash(data) {
    return crypto.createHash('ripemd160').update(data).digest('hex');
}

// Weak Symmetric (VULNERABLE)
function desWeakCipher(plaintext, key) {
    const cipher = crypto.createCipheriv('des-ecb', key.slice(0, 8), null);
    return cipher.update(plaintext, 'utf8', 'hex') + cipher.final('hex');
}

function tripleDes3desCipher(plaintext, key) {
    const iv = crypto.randomBytes(8);
    const cipher = crypto.createCipheriv('des-ede3-cbc', key.slice(0, 24), iv);
    return cipher.update(plaintext, 'utf8', 'hex') + cipher.final('hex');
}

function rc4StreamCipher(plaintext, key) {
    // RC4 is completely broken
    const cipher = crypto.createCipheriv('rc4', key, null);
    return cipher.update(plaintext, 'utf8', 'hex');
}

function blowfishCipher(plaintext, key) {
    const cipher = crypto.createCipheriv('bf-cbc', key.slice(0, 16), Buffer.alloc(8));
    return cipher.update(plaintext, 'utf8', 'hex') + cipher.final('hex');
}

// Weak MAC (VULNERABLE)
function hmacMd5Weak(key, message) {
    return crypto.createHmac('md5', key).update(message).digest('hex');
}

function hmacSha1Weak(key, message) {
    return crypto.createHmac('sha1', key).update(message).digest('hex');
}

// Shor Vulnerable - Asymmetric (VULNERABLE to quantum computers)
function rsaEncryption(data, publicKey) {
    const { publicKey: pk, privateKey: sk } = crypto.generateKeyPairSync('rsa', {
        modulusLength: 2048,
        publicKeyEncoding: { type: 'spki', format: 'pem' },
        privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
    });
    return crypto.publicEncrypt(pk, Buffer.from(data));
}

function dsaSignature(data) {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('dsa', {
        modulusLength: 2048,
        divisorLength: 256
    });
    const sign = crypto.createSign('DSA-SHA256');
    sign.update(data);
    return sign.sign(privateKey);
}

function ecdsaSignature(data) {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', {
        namedCurve: 'prime256v1'
    });
    const sign = crypto.createSign('SHA256');
    sign.update(data);
    return sign.sign(privateKey);
}

function diffieHellmanKeyExchange() {
    const dh = crypto.createDiffieHellman(2048);
    const publicKey = dh.generateKeys();
    return { publicKey, privateKey: dh.getPrivateKey() };
}

function ecdhKeyExchange() {
    const ecdh = crypto.createECDH('prime256v1');
    const publicKey = ecdh.generateKeys();
    return { publicKey, privateKey: ecdh.getPrivateKey() };
}

// Vulnerable Curves
function secp256k1Curve() {
    const ecdh = crypto.createECDH('secp256k1');
    return ecdh.generateKeys();
}

function p384Curve() {
    const ecdh = crypto.createECDH('secp384r1');
    return ecdh.generateKeys();
}

function curve25519Key() {
    return crypto.generateKeyPairSync('x25519');
}

function ed25519Signature(data) {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
    const signature = crypto.sign(null, Buffer.from(data), privateKey);
    return { publicKey, signature };
}

module.exports = {
    md5BrokenHash,
    md4BrokenHash,
    sha1BrokenHash,
    ripemdWeakHash,
    desWeakCipher,
    tripleDes3desCipher,
    rc4StreamCipher,
    blowfishCipher,
    hmacMd5Weak,
    hmacSha1Weak,
    rsaEncryption,
    dsaSignature,
    ecdsaSignature,
    diffieHellmanKeyExchange,
    ecdhKeyExchange,
    secp256k1Curve,
    p384Curve,
    curve25519Key,
    ed25519Signature
};
