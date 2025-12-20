// Quantum Safe - Digital Signatures - TypeScript
import { Dilithium2, Dilithium3, Dilithium5 } from 'crystals-dilithium';
import { MlDsa44, MlDsa65, MlDsa87 } from '@noble/post-quantum/ml-dsa';
import { Falcon512, Falcon1024 } from 'falcon-crypto';
import { sphincs } from 'sphincs-plus';
import * as oqs from 'liboqs-node';

interface SignatureKeyPair {
    publicKey: Uint8Array;
    secretKey: Uint8Array;
}

interface SignatureResult {
    signature: Uint8Array;
    verified: boolean;
}

class MlDsa44Signature {
    async generateKeypair(): Promise<SignatureKeyPair> {
        const { publicKey, secretKey } = await Dilithium2.keypair();
        return { publicKey, secretKey };
    }

    async sign(message: Uint8Array, secretKey: Uint8Array): Promise<Uint8Array> {
        return await Dilithium2.sign(message, secretKey);
    }

    async verify(message: Uint8Array, signature: Uint8Array, publicKey: Uint8Array): Promise<boolean> {
        return await Dilithium2.verify(message, signature, publicKey);
    }
}

class MlDsa65Signature {
    async generateKeypair(): Promise<SignatureKeyPair> {
        const { publicKey, secretKey } = await Dilithium3.keypair();
        return { publicKey, secretKey };
    }

    async sign(message: Uint8Array, secretKey: Uint8Array): Promise<Uint8Array> {
        return await Dilithium3.sign(message, secretKey);
    }
}

class MlDsa87Signature {
    async generateKeypair(): Promise<SignatureKeyPair> {
        const { publicKey, secretKey } = await Dilithium5.keypair();
        return { publicKey, secretKey };
    }
}

class Falcon512Signature {
    async generateKeypair(): Promise<SignatureKeyPair> {
        const { publicKey, secretKey } = await Falcon512.keypair();
        return { publicKey, secretKey };
    }

    async sign(message: Uint8Array, secretKey: Uint8Array): Promise<Uint8Array> {
        return await Falcon512.sign(message, secretKey);
    }

    async verify(message: Uint8Array, signature: Uint8Array, publicKey: Uint8Array): Promise<boolean> {
        return await Falcon512.verify(message, signature, publicKey);
    }
}

class SlhDsaSphincsPlus {
    async generateKeypair(): Promise<SignatureKeyPair> {
        const { publicKey, secretKey } = await sphincs.keypair();
        return { publicKey, secretKey };
    }

    async sign(message: Uint8Array, secretKey: Uint8Array): Promise<Uint8Array> {
        return await sphincs.sign(message, secretKey);
    }
}

class XmssSignature {
    private signer: oqs.Signature;

    constructor() {
        this.signer = new oqs.Signature('Dilithium2');
    }

    generateKeypair(): Uint8Array {
        return this.signer.generateKeypair();
    }

    sign(message: Uint8Array): Uint8Array {
        return this.signer.sign(message);
    }
}

class LmsHashBasedSignature {
    private signer: oqs.Signature;

    constructor() {
        this.signer = new oqs.Signature('Dilithium3');
    }

    generateKeypair(): Uint8Array {
        return this.signer.generateKeypair();
    }
}

export {
    MlDsa44Signature,
    MlDsa65Signature,
    MlDsa87Signature,
    Falcon512Signature,
    SlhDsaSphincsPlus,
    XmssSignature,
    LmsHashBasedSignature,
    SignatureKeyPair,
    SignatureResult
};
