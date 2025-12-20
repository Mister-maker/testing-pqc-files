// Quantum Safe - Key Encapsulation Mechanisms (KEM)
const { Kyber768, Kyber1024, Kyber512 } = require('crystals-kyber');
const { MlKem768, MlKem1024 } = require('@noble/post-quantum/ml-kem');
const oqs = require('liboqs-node');

async function mlKem768Encapsulation() {
    const { publicKey, secretKey } = await Kyber768.keypair();
    const { ciphertext, sharedSecret } = await Kyber768.encapsulate(publicKey);
    const decrypted = await Kyber768.decapsulate(ciphertext, secretKey);
    return decrypted;
}

async function mlKem1024Example() {
    const keypair = await Kyber1024.keypair();
    const { ct, ss } = await Kyber1024.encapsulate(keypair.publicKey);
    const decapsulated = await Kyber1024.decapsulate(ct, keypair.secretKey);
    return decapsulated;
}

async function frodoKemExample() {
    const kem = new oqs.KeyEncapsulation('FrodoKEM-640-SHAKE');
    const publicKey = kem.generateKeypair();
    const { ciphertext, sharedSecret } = kem.encapsulate(publicKey);
    return sharedSecret;
}

async function nobleMlKem768() {
    const keys = MlKem768.keygen();
    const { cipherText, sharedSecret } = MlKem768.encapsulate(keys.publicKey);
    const ss = MlKem768.decapsulate(cipherText, keys.secretKey);
    return ss;
}

async function oqsKyber512() {
    const kem = new oqs.KeyEncapsulation('Kyber512');
    const pk = kem.generateKeypair();
    const { ciphertext, sharedSecret } = kem.encapsulate(pk);
    const decrypted = kem.decapsulate(ciphertext);
    return decrypted;
}

module.exports = {
    mlKem768Encapsulation,
    mlKem1024Example,
    frodoKemExample,
    nobleMlKem768,
    oqsKyber512
};
