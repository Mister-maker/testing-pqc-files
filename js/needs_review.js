// Needs Review - Generic Terms, Ambiguous AES, Library References
const crypto = require('crypto');

// Generic Terms (Need context to determine security)
function encrypt(data, key) {
    // Generic encrypt function
    const cipher = createCipher(key);
    return cipher.update(data, 'utf8', 'hex') + cipher.final('hex');
}

function decrypt(ciphertext, key) {
    const decipher = createDecipher(key);
    return decipher.update(ciphertext, 'hex', 'utf8') + decipher.final('utf8');
}

function sign(message, privateKey) {
    const signer = crypto.createSign('SHA256');
    signer.update(message);
    return signer.sign(privateKey);
}

function verify(message, signature, publicKey) {
    const verifier = crypto.createVerify('SHA256');
    verifier.update(message);
    return verifier.verify(publicKey, signature);
}

function hash(data) {
    // Generic hash - could be any algorithm
    return crypto.createHash('sha256').update(data).digest('hex');
}

function generateKey(length = 32) {
    return crypto.randomBytes(length);
}

function createCipher(key) {
    const iv = crypto.randomBytes(16);
    return crypto.createCipheriv('aes-256-cbc', key, iv);
}

function createDecipher(key, iv) {
    return crypto.createDecipheriv('aes-256-cbc', key, iv);
}

// Ambiguous AES (key size not specified)
function aesEncrypt(plaintext, key) {
    // AES without explicit key size - could be 128, 192, or 256
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-128-cbc', key.slice(0, 16), iv);
    return cipher.update(plaintext, 'utf8', 'hex') + cipher.final('hex');
}

function aesDecrypt(ciphertext, key, iv) {
    const decipher = crypto.createDecipheriv('aes-128-cbc', key.slice(0, 16), iv);
    return decipher.update(ciphertext, 'hex', 'utf8') + decipher.final('utf8');
}

function aesCbcMode(data, key, iv) {
    const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
    return cipher.update(data, 'utf8', 'hex') + cipher.final('hex');
}

function aesEcbMode(data, key) {
    // ECB mode is insecure
    const cipher = crypto.createCipheriv('aes-256-ecb', key, null);
    return cipher.update(data, 'utf8', 'hex') + cipher.final('hex');
}

// Library References
function useOpenSSL() {
    // Node.js crypto uses OpenSSL under the hood
    const openssl = crypto.getCiphers();
    return openssl;
}

function useNodeForge() {
    const forge = require('node-forge');
    const md = forge.md.sha256.create();
    const cipher = forge.cipher.createCipher('AES-CBC', key);
    return { md, cipher };
}

function useWebCrypto() {
    // Web Crypto API (SubtleCrypto)
    const { webcrypto } = require('crypto');
    const subtle = webcrypto.subtle;
    return subtle.generateKey(
        { name: 'AES-GCM', length: 256 },
        true,
        ['encrypt', 'decrypt']
    );
}

function useSodiumNative() {
    const sodium = require('sodium-native');
    const key = Buffer.alloc(sodium.crypto_secretbox_KEYBYTES);
    sodium.randombytes_buf(key);
    return key;
}

module.exports = {
    encrypt,
    decrypt,
    sign,
    verify,
    hash,
    generateKey,
    createCipher,
    aesEncrypt,
    aesDecrypt,
    aesCbcMode,
    aesEcbMode,
    useOpenSSL,
    useNodeForge,
    useWebCrypto,
    useSodiumNative
};
