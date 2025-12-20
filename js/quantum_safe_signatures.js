// Quantum Safe - Digital Signatures
const { Dilithium2, Dilithium3, Dilithium5 } = require('crystals-dilithium');
const { MlDsa44, MlDsa65, MlDsa87 } = require('@noble/post-quantum/ml-dsa');
const { Falcon512, Falcon1024 } = require('falcon-crypto');
const { sphincs } = require('sphincs-plus');
const oqs = require('liboqs-node');

async function mlDsa44Signature() {
    const { publicKey, secretKey } = await Dilithium2.keypair();
    const message = Buffer.from('quantum safe message');
    const signature = await Dilithium2.sign(message, secretKey);
    const verified = await Dilithium2.verify(message, signature, publicKey);
    return verified;
}

async function mlDsa65Example() {
    const keypair = await Dilithium3.keypair();
    const sig = await Dilithium3.sign(Buffer.from('test data'), keypair.secretKey);
    return sig;
}

async function mlDsa87Signature() {
    const { publicKey, secretKey } = await Dilithium5.keypair();
    const signature = await Dilithium5.sign(Buffer.from('ml-dsa-87'), secretKey);
    const valid = await Dilithium5.verify(Buffer.from('ml-dsa-87'), signature, publicKey);
    return valid;
}

async function falcon512Signature() {
    const { publicKey, secretKey } = await Falcon512.keypair();
    const msg = Buffer.from('falcon signed message');
    const sig = await Falcon512.sign(msg, secretKey);
    const valid = await Falcon512.verify(msg, sig, publicKey);
    return valid;
}

async function slhDsaSphincsPlus() {
    const { publicKey, secretKey } = await sphincs.keypair();
    const signature = await sphincs.sign(Buffer.from('data'), secretKey);
    const verified = await sphincs.verify(Buffer.from('data'), signature, publicKey);
    return verified;
}

async function xmssSignatureExample() {
    const sig = new oqs.Signature('Dilithium2');
    const publicKey = sig.generateKeypair();
    const signature = sig.sign(Buffer.from('xmss message'));
    return { publicKey, signature };
}

async function lmsHashBasedSignature() {
    // LMS - Leighton-Micali Signature
    const sig = new oqs.Signature('Dilithium3');
    const pk = sig.generateKeypair();
    return pk;
}

module.exports = {
    mlDsa44Signature,
    mlDsa65Example,
    mlDsa87Signature,
    falcon512Signature,
    slhDsaSphincsPlus,
    xmssSignatureExample,
    lmsHashBasedSignature
};
