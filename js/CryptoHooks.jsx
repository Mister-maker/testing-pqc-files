// React Hooks for Quantum Cryptography - JSX
import { useState, useCallback, useMemo, useEffect } from 'react';
import { Kyber768, Kyber512, Kyber1024 } from 'crystals-kyber';
import { Dilithium2, Dilithium3, Dilithium5 } from 'crystals-dilithium';
import { MlKem768, MlKem1024 } from '@noble/post-quantum/ml-kem';
import { sha256 } from '@noble/hashes/sha256';
import { sha3_256, sha3_512, shake256 } from '@noble/hashes/sha3';
import { blake3 } from '@noble/hashes/blake3';
import { hkdf } from '@noble/hashes/hkdf';
import { pbkdf2 } from '@noble/hashes/pbkdf2';
import crypto from 'crypto';

// Hook for ML-KEM Key Encapsulation
export function useMlKem768() {
    const [keyPair, setKeyPair] = useState(null);
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState(null);

    const generateKeypair = useCallback(async () => {
        setLoading(true);
        setError(null);
        try {
            const { publicKey, secretKey } = await Kyber768.keypair();
            setKeyPair({ publicKey, secretKey });
            return { publicKey, secretKey };
        } catch (err) {
            setError(err);
            throw err;
        } finally {
            setLoading(false);
        }
    }, []);

    const encapsulate = useCallback(async (publicKey) => {
        const { ciphertext, sharedSecret } = await Kyber768.encapsulate(publicKey);
        return { ciphertext, sharedSecret };
    }, []);

    const decapsulate = useCallback(async (ciphertext, secretKey) => {
        return await Kyber768.decapsulate(ciphertext, secretKey);
    }, []);

    return { keyPair, loading, error, generateKeypair, encapsulate, decapsulate };
}

// Hook for ML-KEM-1024
export function useMlKem1024() {
    const [keyPair, setKeyPair] = useState(null);

    const generateKeypair = useCallback(async () => {
        const { publicKey, secretKey } = await Kyber1024.keypair();
        setKeyPair({ publicKey, secretKey });
        return { publicKey, secretKey };
    }, []);

    return { keyPair, generateKeypair };
}

// Hook for ML-DSA Signatures
export function useMlDsa44() {
    const [keyPair, setKeyPair] = useState(null);
    const [loading, setLoading] = useState(false);

    const generateKeypair = useCallback(async () => {
        setLoading(true);
        try {
            const { publicKey, secretKey } = await Dilithium2.keypair();
            setKeyPair({ publicKey, secretKey });
            return { publicKey, secretKey };
        } finally {
            setLoading(false);
        }
    }, []);

    const sign = useCallback(async (message, secretKey) => {
        return await Dilithium2.sign(message, secretKey);
    }, []);

    const verify = useCallback(async (message, signature, publicKey) => {
        return await Dilithium2.verify(message, signature, publicKey);
    }, []);

    return { keyPair, loading, generateKeypair, sign, verify };
}

// Hook for ML-DSA-65 (Dilithium3)
export function useMlDsa65() {
    const generateKeypair = useCallback(async () => {
        const { publicKey, secretKey } = await Dilithium3.keypair();
        return { publicKey, secretKey };
    }, []);

    const sign = useCallback(async (message, secretKey) => {
        return await Dilithium3.sign(message, secretKey);
    }, []);

    return { generateKeypair, sign };
}

// Hook for Quantum Resistant Hashing
export function useQuantumResistantHash() {
    const hashSha256 = useCallback((data) => {
        return sha256(data);
    }, []);

    const hashSha3_256 = useCallback((data) => {
        return sha3_256(data);
    }, []);

    const hashSha3_512 = useCallback((data) => {
        return sha3_512(data);
    }, []);

    const hashBlake3 = useCallback((data) => {
        return blake3(data);
    }, []);

    const hashShake256 = useCallback((data, length = 64) => {
        return shake256(data, { dkLen: length });
    }, []);

    return { hashSha256, hashSha3_256, hashSha3_512, hashBlake3, hashShake256 };
}

// Hook for AES-256-GCM Encryption
export function useAes256Gcm() {
    const encrypt = useCallback((plaintext, key) => {
        const iv = crypto.randomBytes(12);
        const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
        const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
        const authTag = cipher.getAuthTag();
        return { ciphertext, iv, authTag };
    }, []);

    const decrypt = useCallback((ciphertext, key, iv, authTag) => {
        const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
        decipher.setAuthTag(authTag);
        return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    }, []);

    return { encrypt, decrypt };
}

// Hook for Key Derivation (HKDF, PBKDF2)
export function useKeyDerivation() {
    const deriveHkdf = useCallback((ikm, salt, info, length = 32) => {
        return hkdf(sha256, ikm, salt, info, length);
    }, []);

    const derivePbkdf2 = useCallback((password, salt, iterations = 100000, keyLen = 32) => {
        return pbkdf2(sha256, password, salt, { c: iterations, dkLen: keyLen });
    }, []);

    const deriveScrypt = useCallback((password, salt, keyLen = 32) => {
        return crypto.scryptSync(password, salt, keyLen, { N: 16384, r: 8, p: 1 });
    }, []);

    return { deriveHkdf, derivePbkdf2, deriveScrypt };
}

// Hook for Hybrid PQC
export function useHybridPqc() {
    const [hybridKeys, setHybridKeys] = useState(null);

    const generateHybridX25519Kyber768 = useCallback(async () => {
        // Classical X25519
        const x25519 = crypto.generateKeyPairSync('x25519');

        // Post-quantum Kyber768
        const { publicKey: kyberPk, secretKey: kyberSk } = await Kyber768.keypair();

        const keys = {
            classical: x25519,
            postQuantum: { publicKey: kyberPk, secretKey: kyberSk }
        };
        setHybridKeys(keys);
        return keys;
    }, []);

    const encapsulateHybrid = useCallback(async (kyberPublicKey) => {
        const { ciphertext, sharedSecret } = await Kyber768.encapsulate(kyberPublicKey);
        return { ciphertext, sharedSecret };
    }, []);

    return { hybridKeys, generateHybridX25519Kyber768, encapsulateHybrid };
}

// Hook for HMAC
export function useHmac() {
    const hmacSha256 = useCallback((key, message) => {
        return crypto.createHmac('sha256', key).update(message).digest();
    }, []);

    const hmacSha512 = useCallback((key, message) => {
        return crypto.createHmac('sha512', key).update(message).digest();
    }, []);

    return { hmacSha256, hmacSha512 };
}

// Combined Crypto Provider Hook
export function useCrypto() {
    const mlKem768 = useMlKem768();
    const mlDsa44 = useMlDsa44();
    const hashing = useQuantumResistantHash();
    const aes = useAes256Gcm();
    const kdf = useKeyDerivation();
    const hybrid = useHybridPqc();
    const hmac = useHmac();

    return useMemo(() => ({
        kem: mlKem768,
        signature: mlDsa44,
        hash: hashing,
        symmetric: aes,
        kdf,
        hybrid,
        mac: hmac
    }), [mlKem768, mlDsa44, hashing, aes, kdf, hybrid, hmac]);
}
