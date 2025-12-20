// Quantum Safe - Hybrid PQC Implementations - TypeScript
import { Kyber768 } from 'crystals-kyber';
import { MlKem768 } from '@noble/post-quantum/ml-kem';
import { x25519 } from '@noble/curves/ed25519';
import { hkdf } from '@noble/hashes/hkdf';
import { sha256 } from '@noble/hashes/sha256';
import * as crypto from 'crypto';

interface HybridKeyPair {
    classicalPublic: Uint8Array;
    classicalPrivate: Uint8Array;
    pqPublic: Uint8Array;
    pqSecret: Uint8Array;
}

interface HybridEncapsulation {
    classicalCiphertext: Uint8Array;
    pqCiphertext: Uint8Array;
    sharedSecret: Uint8Array;
}

// Hybrid X25519 + Kyber768
class HybridX25519Kyber768 {
    async generateKeypair(): Promise<HybridKeyPair> {
        // Classical X25519
        const x25519Private = crypto.randomBytes(32);
        const x25519Public = x25519.getPublicKey(x25519Private);

        // Post-quantum Kyber768
        const { publicKey: kyberPk, secretKey: kyberSk } = await Kyber768.keypair();

        return {
            classicalPublic: x25519Public,
            classicalPrivate: x25519Private,
            pqPublic: kyberPk,
            pqSecret: kyberSk
        };
    }

    async encapsulate(hybridPublic: HybridKeyPair): Promise<HybridEncapsulation> {
        // Kyber768 encapsulation
        const { ciphertext: kyberCt, sharedSecret: kyberSs } = await Kyber768.encapsulate(hybridPublic.pqPublic);

        // Combine shared secrets with HKDF
        const combined = Buffer.concat([hybridPublic.classicalPublic, kyberSs]);
        const finalKey = hkdf(sha256, combined, undefined, 'hybrid-kem', 32);

        return {
            classicalCiphertext: hybridPublic.classicalPublic,
            pqCiphertext: kyberCt,
            sharedSecret: finalKey
        };
    }
}

// Hybrid ECDH + ML-KEM
class HybridEcdhMlKem {
    async generateHybridKey(): Promise<{ ecdhPublic: Buffer; mlkemKeys: any }> {
        // ECDH
        const ecdh = crypto.createECDH('prime256v1');
        const ecdhPublic = ecdh.generateKeys();

        // ML-KEM (Kyber768)
        const mlkemKeys = MlKem768.keygen();

        return { ecdhPublic, mlkemKeys };
    }

    async encapsulate(mlkemPublicKey: Uint8Array): Promise<{ cipherText: Uint8Array; sharedSecret: Uint8Array }> {
        return MlKem768.encapsulate(mlkemPublicKey);
    }
}

// Hybrid TLS with PQC
class HybridTlsPqc {
    async setup(): Promise<{ x25519Keys: any; kyberKeys: any }> {
        const x25519Private = crypto.randomBytes(32);
        const x25519Public = x25519.getPublicKey(x25519Private);

        const kyberKeys = await Kyber768.keypair();

        return {
            x25519Keys: { public: x25519Public, private: x25519Private },
            kyberKeys
        };
    }
}

// X25519Kyber768Draft00 IETF draft
class X25519Kyber768Draft00 {
    async generateHybridPublic(): Promise<Uint8Array> {
        const x25519Private = crypto.randomBytes(32);
        const x25519Public = x25519.getPublicKey(x25519Private);

        const { publicKey: kyberPk } = await Kyber768.keypair();

        return Buffer.concat([x25519Public, kyberPk]);
    }

    async encapsulateHybrid(x25519Public: Uint8Array, kyberPk: Uint8Array): Promise<Uint8Array> {
        const { ciphertext, sharedSecret } = await Kyber768.encapsulate(kyberPk);

        const combined = Buffer.concat([x25519Public, sharedSecret]);
        return hkdf(sha256, combined, undefined, 'x25519-kyber768-draft00', 32);
    }
}

// ECDH + Kyber Composite
class EcdhKyberComposite {
    async generateCompositeSecret(): Promise<Uint8Array> {
        // ECDH P-384
        const ecdh = crypto.createECDH('secp384r1');
        const ecPublic = ecdh.generateKeys();

        // Kyber768
        const { publicKey: kyberPk } = await Kyber768.keypair();
        const { ciphertext, sharedSecret } = await Kyber768.encapsulate(kyberPk);

        // Combine with HKDF
        const compositeSecret = hkdf(
            sha256,
            Buffer.concat([ecdh.getPrivateKey(), sharedSecret]),
            undefined,
            'composite-kem',
            32
        );

        return compositeSecret;
    }
}

export {
    HybridX25519Kyber768,
    HybridEcdhMlKem,
    HybridTlsPqc,
    X25519Kyber768Draft00,
    EcdhKyberComposite,
    HybridKeyPair,
    HybridEncapsulation
};
