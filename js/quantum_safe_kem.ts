// Quantum Safe - Key Encapsulation Mechanisms (KEM) - TypeScript
import { Kyber768, Kyber1024, Kyber512 } from 'crystals-kyber';
import { MlKem768, MlKem1024, MlKem512 } from '@noble/post-quantum/ml-kem';
import * as oqs from 'liboqs-node';

interface KeyPair {
    publicKey: Uint8Array;
    secretKey: Uint8Array;
}

interface EncapsulationResult {
    ciphertext: Uint8Array;
    sharedSecret: Uint8Array;
}

class MlKem768Kem {
    async generateKeypair(): Promise<KeyPair> {
        const { publicKey, secretKey } = await Kyber768.keypair();
        return { publicKey, secretKey };
    }

    async encapsulate(publicKey: Uint8Array): Promise<EncapsulationResult> {
        const { ciphertext, sharedSecret } = await Kyber768.encapsulate(publicKey);
        return { ciphertext, sharedSecret };
    }

    async decapsulate(ciphertext: Uint8Array, secretKey: Uint8Array): Promise<Uint8Array> {
        return await Kyber768.decapsulate(ciphertext, secretKey);
    }
}

class MlKem1024Kem {
    async generateKeypair(): Promise<KeyPair> {
        const { publicKey, secretKey } = await Kyber1024.keypair();
        return { publicKey, secretKey };
    }

    async encapsulate(publicKey: Uint8Array): Promise<EncapsulationResult> {
        const { ciphertext, sharedSecret } = await Kyber1024.encapsulate(publicKey);
        return { ciphertext, sharedSecret };
    }
}

class MlKem512Kem {
    async generateKeypair(): Promise<KeyPair> {
        const { publicKey, secretKey } = await Kyber512.keypair();
        return { publicKey, secretKey };
    }
}

class FrodoKemWrapper {
    private kem: oqs.KeyEncapsulation;

    constructor() {
        this.kem = new oqs.KeyEncapsulation('FrodoKEM-640-SHAKE');
    }

    generateKeypair(): Uint8Array {
        return this.kem.generateKeypair();
    }

    encapsulate(publicKey: Uint8Array): EncapsulationResult {
        const { ciphertext, sharedSecret } = this.kem.encapsulate(publicKey);
        return { ciphertext, sharedSecret };
    }
}

// Noble Post-Quantum ML-KEM
function nobleMlKem768(): { publicKey: Uint8Array; secretKey: Uint8Array } {
    const keys = MlKem768.keygen();
    return { publicKey: keys.publicKey, secretKey: keys.secretKey };
}

function nobleMlKem1024Encapsulate(publicKey: Uint8Array): { cipherText: Uint8Array; sharedSecret: Uint8Array } {
    return MlKem1024.encapsulate(publicKey);
}

async function kyberKeyGeneration(): Promise<KeyPair> {
    const kem = new MlKem768Kem();
    return await kem.generateKeypair();
}

export {
    MlKem768Kem,
    MlKem1024Kem,
    MlKem512Kem,
    FrodoKemWrapper,
    nobleMlKem768,
    nobleMlKem1024Encapsulate,
    kyberKeyGeneration,
    KeyPair,
    EncapsulationResult
};
