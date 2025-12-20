// Quantum Cryptography React Components - JSX
import React, { useState, useEffect, useCallback } from 'react';
import { Kyber768, Kyber1024 } from 'crystals-kyber';
import { Dilithium2, Dilithium3 } from 'crystals-dilithium';
import { MlKem768 } from '@noble/post-quantum/ml-kem';
import { MlDsa44, MlDsa65 } from '@noble/post-quantum/ml-dsa';
import { sha256 } from '@noble/hashes/sha256';
import { sha3_256 } from '@noble/hashes/sha3';
import crypto from 'crypto';

// Quantum Safe KEM Component
export function QuantumSafeKemDemo() {
    const [keyPair, setKeyPair] = useState(null);
    const [sharedSecret, setSharedSecret] = useState(null);
    const [loading, setLoading] = useState(false);

    const generateMlKem768Keys = useCallback(async () => {
        setLoading(true);
        try {
            const { publicKey, secretKey } = await Kyber768.keypair();
            setKeyPair({ publicKey, secretKey });
        } finally {
            setLoading(false);
        }
    }, []);

    const encapsulateMlKem768 = useCallback(async () => {
        if (!keyPair) return;
        const { ciphertext, sharedSecret } = await Kyber768.encapsulate(keyPair.publicKey);
        setSharedSecret(sharedSecret);
    }, [keyPair]);

    const generateKyber1024Keys = async () => {
        const { publicKey, secretKey } = await Kyber1024.keypair();
        return { publicKey, secretKey };
    };

    const nobleMlKem768Demo = () => {
        const keys = MlKem768.keygen();
        const { cipherText, sharedSecret } = MlKem768.encapsulate(keys.publicKey);
        return { keys, cipherText, sharedSecret };
    };

    return (
        <div className="quantum-safe-kem">
            <h2>ML-KEM (Kyber) Key Encapsulation</h2>
            <button onClick={generateMlKem768Keys} disabled={loading}>
                Generate Kyber768 Keys
            </button>
            <button onClick={encapsulateMlKem768} disabled={!keyPair}>
                Encapsulate
            </button>
            {sharedSecret && <p>Shared Secret Generated!</p>}
        </div>
    );
}

// Quantum Safe Signature Component
export function QuantumSafeSignatureDemo() {
    const [signatureKeyPair, setSignatureKeyPair] = useState(null);
    const [signature, setSignature] = useState(null);
    const [message, setMessage] = useState('');

    const generateMlDsa44Keys = useCallback(async () => {
        const { publicKey, secretKey } = await Dilithium2.keypair();
        setSignatureKeyPair({ publicKey, secretKey });
    }, []);

    const signWithMlDsa44 = useCallback(async () => {
        if (!signatureKeyPair || !message) return;
        const sig = await Dilithium2.sign(Buffer.from(message), signatureKeyPair.secretKey);
        setSignature(sig);
    }, [signatureKeyPair, message]);

    const verifyMlDsa44Signature = async () => {
        if (!signature || !signatureKeyPair) return false;
        return await Dilithium2.verify(Buffer.from(message), signature, signatureKeyPair.publicKey);
    };

    const generateMlDsa65Keys = async () => {
        const { publicKey, secretKey } = await Dilithium3.keypair();
        return { publicKey, secretKey };
    };

    const nobleMlDsa44Demo = () => {
        const keys = MlDsa44.keygen();
        const msg = new TextEncoder().encode('test message');
        const sig = MlDsa44.sign(keys.secretKey, msg);
        return MlDsa44.verify(keys.publicKey, msg, sig);
    };

    return (
        <div className="quantum-safe-signature">
            <h2>ML-DSA (Dilithium) Digital Signatures</h2>
            <input
                value={message}
                onChange={(e) => setMessage(e.target.value)}
                placeholder="Message to sign"
            />
            <button onClick={generateMlDsa44Keys}>Generate Dilithium2 Keys</button>
            <button onClick={signWithMlDsa44} disabled={!signatureKeyPair}>Sign</button>
            {signature && <p>Message Signed!</p>}
        </div>
    );
}

// Quantum Resistant Hashing Component
export function QuantumResistantHashDemo() {
    const [inputData, setInputData] = useState('');
    const [hashResults, setHashResults] = useState({});

    const computeHashes = useCallback(() => {
        const data = Buffer.from(inputData);

        // SHA-256 (quantum resistant)
        const sha256Hash = crypto.createHash('sha256').update(data).digest('hex');

        // SHA-512 (quantum resistant)
        const sha512Hash = crypto.createHash('sha512').update(data).digest('hex');

        // SHA3-256 (quantum resistant)
        const sha3_256Hash = Buffer.from(sha3_256(data)).toString('hex');

        // Noble SHA-256
        const nobleSha256 = Buffer.from(sha256(data)).toString('hex');

        setHashResults({
            sha256: sha256Hash,
            sha512: sha512Hash,
            sha3_256: sha3_256Hash,
            nobleSha256: nobleSha256
        });
    }, [inputData]);

    return (
        <div className="quantum-resistant-hash">
            <h2>Quantum Resistant Hashing</h2>
            <input
                value={inputData}
                onChange={(e) => setInputData(e.target.value)}
                placeholder="Data to hash"
            />
            <button onClick={computeHashes}>Compute Hashes</button>
            <div>
                {Object.entries(hashResults).map(([algo, hash]) => (
                    <p key={algo}><strong>{algo}:</strong> {hash?.substring(0, 32)}...</p>
                ))}
            </div>
        </div>
    );
}

// Quantum Vulnerable Warning Component (Educational)
export function QuantumVulnerableWarning() {
    const [vulnerableDemo, setVulnerableDemo] = useState(null);

    const showVulnerableAlgorithms = () => {
        // These are vulnerable to quantum attacks - DO NOT USE
        const md5Hash = crypto.createHash('md5').update('test').digest('hex');
        const sha1Hash = crypto.createHash('sha1').update('test').digest('hex');

        // RSA - vulnerable to Shor's algorithm
        const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
            modulusLength: 2048
        });

        // ECDSA - vulnerable to Shor's algorithm
        const ecdsaKeys = crypto.generateKeyPairSync('ec', {
            namedCurve: 'prime256v1'
        });

        setVulnerableDemo({
            md5: md5Hash,
            sha1: sha1Hash,
            rsaGenerated: true,
            ecdsaGenerated: true
        });
    };

    return (
        <div className="quantum-vulnerable-warning">
            <h2>Quantum Vulnerable Algorithms (Educational Demo)</h2>
            <p className="warning">These algorithms are NOT quantum safe!</p>
            <button onClick={showVulnerableAlgorithms}>Show Vulnerable Examples</button>
            {vulnerableDemo && (
                <div>
                    <p>MD5 (broken): {vulnerableDemo.md5}</p>
                    <p>SHA1 (broken): {vulnerableDemo.sha1}</p>
                    <p>RSA (Shor vulnerable): Generated</p>
                    <p>ECDSA (Shor vulnerable): Generated</p>
                </div>
            )}
        </div>
    );
}

// Hybrid PQC Component
export function HybridPqcDemo() {
    const [hybridKeys, setHybridKeys] = useState(null);

    const generateHybridX25519Kyber768 = async () => {
        // Classical X25519
        const x25519Keys = crypto.generateKeyPairSync('x25519');

        // Post-quantum Kyber768
        const { publicKey: kyberPk, secretKey: kyberSk } = await Kyber768.keypair();

        setHybridKeys({
            x25519: x25519Keys,
            kyber768: { publicKey: kyberPk, secretKey: kyberSk }
        });
    };

    return (
        <div className="hybrid-pqc">
            <h2>Hybrid X25519 + Kyber768</h2>
            <button onClick={generateHybridX25519Kyber768}>
                Generate Hybrid Keys
            </button>
            {hybridKeys && <p>Hybrid key pair generated successfully!</p>}
        </div>
    );
}

// Main Crypto Dashboard
export default function CryptoDashboard() {
    return (
        <div className="crypto-dashboard">
            <h1>Post-Quantum Cryptography Demo</h1>
            <QuantumSafeKemDemo />
            <QuantumSafeSignatureDemo />
            <QuantumResistantHashDemo />
            <HybridPqcDemo />
            <QuantumVulnerableWarning />
        </div>
    );
}
