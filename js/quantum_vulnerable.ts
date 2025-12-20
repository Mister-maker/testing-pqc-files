// Quantum Vulnerable - Broken/Weak Algorithms (DO NOT USE IN PRODUCTION) - TypeScript
import * as crypto from 'crypto';
import * as forge from 'node-forge';

interface KeyPairResult {
    publicKey: crypto.KeyObject;
    privateKey: crypto.KeyObject;
}

// Broken Hash (VULNERABLE)
function md5BrokenHash(data: Buffer): string {
    return crypto.createHash('md5').update(data).digest('hex');
}

function md4BrokenHash(data: string): string {
    return forge.md.md4.create().update(data).digest().toHex();
}

function sha1BrokenHash(data: Buffer): string {
    return crypto.createHash('sha1').update(data).digest('hex');
}

function ripemdWeakHash(data: Buffer): string {
    return crypto.createHash('ripemd160').update(data).digest('hex');
}

// Weak Symmetric (VULNERABLE)
class DesWeakCipher {
    encrypt(plaintext: Buffer, key: Buffer): string {
        const cipher = crypto.createCipheriv('des-ecb', key.slice(0, 8), null);
        return cipher.update(plaintext, undefined, 'hex') + cipher.final('hex');
    }
}

class TripleDes3desCipher {
    encrypt(plaintext: Buffer, key: Buffer): string {
        const iv = crypto.randomBytes(8);
        const cipher = crypto.createCipheriv('des-ede3-cbc', key.slice(0, 24), iv);
        return cipher.update(plaintext, undefined, 'hex') + cipher.final('hex');
    }
}

class Rc4StreamCipher {
    encrypt(plaintext: Buffer, key: Buffer): string {
        // RC4 is completely broken
        const cipher = crypto.createCipheriv('rc4', key, null);
        return cipher.update(plaintext, undefined, 'hex');
    }
}

class BlowfishCipher {
    encrypt(plaintext: Buffer, key: Buffer): string {
        const cipher = crypto.createCipheriv('bf-cbc', key.slice(0, 16), Buffer.alloc(8));
        return cipher.update(plaintext, undefined, 'hex') + cipher.final('hex');
    }
}

// Weak MAC (VULNERABLE)
function hmacMd5Weak(key: Buffer, message: Buffer): string {
    return crypto.createHmac('md5', key).update(message).digest('hex');
}

function hmacSha1Weak(key: Buffer, message: Buffer): string {
    return crypto.createHmac('sha1', key).update(message).digest('hex');
}

// Shor Vulnerable - Asymmetric (VULNERABLE to quantum computers)
class RsaEncryption {
    generateKeypair(): KeyPairResult {
        const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
            modulusLength: 2048,
            publicKeyEncoding: { type: 'spki', format: 'pem' },
            privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
        });
        return {
            publicKey: crypto.createPublicKey(publicKey),
            privateKey: crypto.createPrivateKey(privateKey)
        };
    }

    encrypt(data: Buffer, publicKey: crypto.KeyObject): Buffer {
        return crypto.publicEncrypt(publicKey, data);
    }
}

class DsaSignature {
    generateKeypair(): KeyPairResult {
        const { publicKey, privateKey } = crypto.generateKeyPairSync('dsa', {
            modulusLength: 2048,
            divisorLength: 256
        });
        return { publicKey, privateKey };
    }

    sign(data: Buffer, privateKey: crypto.KeyObject): Buffer {
        const sign = crypto.createSign('DSA-SHA256');
        sign.update(data);
        return sign.sign(privateKey);
    }
}

class EcdsaSignature {
    generateKeypair(): KeyPairResult {
        const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', {
            namedCurve: 'prime256v1'
        });
        return { publicKey, privateKey };
    }

    sign(data: Buffer, privateKey: crypto.KeyObject): Buffer {
        const sign = crypto.createSign('SHA256');
        sign.update(data);
        return sign.sign(privateKey);
    }
}

class DiffieHellmanKeyExchange {
    generate(): { publicKey: Buffer; privateKey: Buffer } {
        const dh = crypto.createDiffieHellman(2048);
        const publicKey = dh.generateKeys();
        return { publicKey, privateKey: dh.getPrivateKey() };
    }
}

class EcdhKeyExchange {
    generate(): { publicKey: Buffer; privateKey: Buffer } {
        const ecdh = crypto.createECDH('prime256v1');
        const publicKey = ecdh.generateKeys();
        return { publicKey, privateKey: ecdh.getPrivateKey() };
    }
}

// Vulnerable Curves
class Secp256k1Curve {
    generate(): Buffer {
        const ecdh = crypto.createECDH('secp256k1');
        return ecdh.generateKeys();
    }
}

class P384Curve {
    generate(): Buffer {
        const ecdh = crypto.createECDH('secp384r1');
        return ecdh.generateKeys();
    }
}

class Curve25519Key {
    generate(): KeyPairResult {
        const { publicKey, privateKey } = crypto.generateKeyPairSync('x25519');
        return { publicKey, privateKey };
    }
}

class Ed25519Signature {
    generate(): KeyPairResult {
        const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
        return { publicKey, privateKey };
    }

    sign(data: Buffer, privateKey: crypto.KeyObject): Buffer {
        return crypto.sign(null, data, privateKey);
    }
}

export {
    md5BrokenHash,
    md4BrokenHash,
    sha1BrokenHash,
    ripemdWeakHash,
    DesWeakCipher,
    TripleDes3desCipher,
    Rc4StreamCipher,
    BlowfishCipher,
    hmacMd5Weak,
    hmacSha1Weak,
    RsaEncryption,
    DsaSignature,
    EcdsaSignature,
    DiffieHellmanKeyExchange,
    EcdhKeyExchange,
    Secp256k1Curve,
    P384Curve,
    Curve25519Key,
    Ed25519Signature,
    KeyPairResult
};
