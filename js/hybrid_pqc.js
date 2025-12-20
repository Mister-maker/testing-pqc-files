// Quantum Safe - Hybrid PQC Implementations
const { Kyber768 } = require('crystals-kyber');
const { MlKem768 } = require('@noble/post-quantum/ml-kem');
const { x25519 } = require('@noble/curves/ed25519');
const { hkdf } = require('@noble/hashes/hkdf');
const { sha256 } = require('@noble/hashes/sha256');
const crypto = require('crypto');

// Hybrid X25519 + Kyber768
async function hybridX25519Kyber768() {
    // Classical X25519
    const x25519PrivateKey = crypto.randomBytes(32);
    const x25519PublicKey = x25519.getPublicKey(x25519PrivateKey);

    // Post-quantum Kyber768
    const { publicKey: kyberPk, secretKey: kyberSk } = await Kyber768.keypair();
    const { ciphertext: kyberCt, sharedSecret: kyberSs } = await Kyber768.encapsulate(kyberPk);

    // Combine shared secrets with HKDF
    const combinedSecret = Buffer.concat([x25519PublicKey, kyberSs]);
    const finalKey = hkdf(sha256, combinedSecret, null, 'hybrid-kem', 32);

    return { finalKey, kyberCt };
}

async function hybridEcdhMlKem() {
    // ECDH + ML-KEM hybrid
    const ecdh = crypto.createECDH('prime256v1');
    const ecdhPublicKey = ecdh.generateKeys();

    const mlkemKeys = MlKem768.keygen();
    const { cipherText, sharedSecret } = MlKem768.encapsulate(mlkemKeys.publicKey);

    const ecdhSecret = ecdh.computeSecret(ecdhPublicKey);
    const combined = Buffer.concat([ecdhSecret, sharedSecret]);

    return { combined, cipherText };
}

async function hybridTlsPqc() {
    // Hybrid TLS with PQC - simulated
    const x25519Keys = {
        privateKey: crypto.randomBytes(32),
        publicKey: x25519.getPublicKey(crypto.randomBytes(32))
    };

    const kyberKeys = await Kyber768.keypair();

    // X25519Kyber768Draft00 style combination
    return { x25519Keys, kyberKeys };
}

async function x25519Kyber768Draft00() {
    // IETF draft hybrid key exchange
    const x25519Private = crypto.randomBytes(32);
    const x25519Public = x25519.getPublicKey(x25519Private);

    const { publicKey: kyberPk, secretKey: kyberSk } = await Kyber768.keypair();

    return {
        hybridPublic: Buffer.concat([x25519Public, kyberPk]),
        hybridSecret: Buffer.concat([x25519Private, kyberSk])
    };
}

async function ecdhKyberComposite() {
    // Composite key encapsulation
    const ecdh = crypto.createECDH('secp384r1');
    const ecPublic = ecdh.generateKeys();

    const { publicKey: kyberPk, secretKey: kyberSk } = await Kyber768.keypair();
    const { ciphertext, sharedSecret } = await Kyber768.encapsulate(kyberPk);

    const compositeSecret = hkdf(
        sha256,
        Buffer.concat([ecdh.getPrivateKey(), sharedSecret]),
        null,
        'composite-kem',
        32
    );

    return { compositeSecret, ciphertext, ecPublic };
}

module.exports = {
    hybridX25519Kyber768,
    hybridEcdhMlKem,
    hybridTlsPqc,
    x25519Kyber768Draft00,
    ecdhKyberComposite
};
