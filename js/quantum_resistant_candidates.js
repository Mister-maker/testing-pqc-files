// Quantum Resistant - PQC Candidates (KEM and Signatures)
const oqs = require('liboqs-node');

// PQC Candidate KEMs
async function ntruKemExample() {
    const kem = new oqs.KeyEncapsulation('NTRU-HPS-2048-509');
    const publicKey = kem.generateKeypair();
    const { ciphertext, sharedSecret } = kem.encapsulate(publicKey);
    const decrypted = kem.decapsulate(ciphertext);
    return decrypted;
}

async function classicMcElieceKem() {
    const kem = new oqs.KeyEncapsulation('Classic-McEliece-348864');
    const pk = kem.generateKeypair();
    const { ciphertext, sharedSecret } = kem.encapsulate(pk);
    return sharedSecret;
}

async function hqcKemExample() {
    const kem = new oqs.KeyEncapsulation('HQC-128');
    const publicKey = kem.generateKeypair();
    const { ct, ss } = kem.encapsulate(publicKey);
    return ss;
}

async function bikeKemExample() {
    const kem = new oqs.KeyEncapsulation('BIKE-L1');
    const pk = kem.generateKeypair();
    const { ciphertext, sharedSecret } = kem.encapsulate(pk);
    return sharedSecret;
}

async function sikeVulnerableKem() {
    // SIKE - Supersingular Isogeny Key Encapsulation (VULNERABLE - broken)
    const kem = new oqs.KeyEncapsulation('SIKE-p434');
    const pk = kem.generateKeypair();
    return pk;
}

// PQC Candidate Signatures
async function picnicSignature() {
    const sig = new oqs.Signature('Picnic-L1-full');
    const publicKey = sig.generateKeypair();
    const signature = sig.sign(Buffer.from('picnic message'));
    return { publicKey, signature };
}

async function rainbowVulnerableSignature() {
    // Rainbow signature scheme (VULNERABLE - broken)
    const sig = new oqs.Signature('Rainbow-I-Classic');
    const pk = sig.generateKeypair();
    return pk;
}

async function gemssSignatureExample() {
    // GeMSS - Great Multivariate Signature Scheme
    const sig = new oqs.Signature('GeMSS-128');
    const keypair = sig.generateKeypair();
    return keypair;
}

module.exports = {
    ntruKemExample,
    classicMcElieceKem,
    hqcKemExample,
    bikeKemExample,
    sikeVulnerableKem,
    picnicSignature,
    rainbowVulnerableSignature,
    gemssSignatureExample
};
