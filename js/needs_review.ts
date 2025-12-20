// Needs Review - Generic Terms, Ambiguous AES, Library References - TypeScript
import * as crypto from 'crypto';

interface CryptoResult {
    data: Buffer;
    iv?: Buffer;
    tag?: Buffer;
}

// Generic Terms (Need context to determine security)
class CryptoService {
    encrypt(data: Buffer, key: Buffer): CryptoResult {
        const iv = crypto.randomBytes(16);
        const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
        const encrypted = Buffer.concat([cipher.update(data), cipher.final()]);
        return { data: encrypted, iv };
    }

    decrypt(ciphertext: Buffer, key: Buffer, iv: Buffer): Buffer {
        const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
        return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    }

    sign(message: Buffer, privateKey: crypto.KeyObject): Buffer {
        const signer = crypto.createSign('SHA256');
        signer.update(message);
        return signer.sign(privateKey);
    }

    verify(message: Buffer, signature: Buffer, publicKey: crypto.KeyObject): boolean {
        const verifier = crypto.createVerify('SHA256');
        verifier.update(message);
        return verifier.verify(publicKey, signature);
    }

    hash(data: Buffer): Buffer {
        return crypto.createHash('sha256').update(data).digest();
    }

    generateKey(length: number = 32): Buffer {
        return crypto.randomBytes(length);
    }

    createCipher(key: Buffer): crypto.Cipher {
        const iv = crypto.randomBytes(16);
        return crypto.createCipheriv('aes-256-cbc', key, iv);
    }
}

// Ambiguous AES (key size not specified)
class AesCipher {
    aesEncrypt(plaintext: Buffer, key: Buffer): string {
        // AES without explicit key size - could be 128, 192, or 256
        const iv = crypto.randomBytes(16);
        const cipher = crypto.createCipheriv('aes-128-cbc', key.slice(0, 16), iv);
        return cipher.update(plaintext, undefined, 'hex') + cipher.final('hex');
    }

    aesDecrypt(ciphertext: string, key: Buffer, iv: Buffer): Buffer {
        const decipher = crypto.createDecipheriv('aes-128-cbc', key.slice(0, 16), iv);
        return Buffer.concat([
            decipher.update(Buffer.from(ciphertext, 'hex')),
            decipher.final()
        ]);
    }

    aesCbcMode(data: Buffer, key: Buffer, iv: Buffer): string {
        const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
        return cipher.update(data, undefined, 'hex') + cipher.final('hex');
    }

    aesEcbMode(data: Buffer, key: Buffer): string {
        // ECB mode is insecure
        const cipher = crypto.createCipheriv('aes-256-ecb', key, null);
        return cipher.update(data, undefined, 'hex') + cipher.final('hex');
    }
}

// Library References
class LibraryUsage {
    useOpenSSL(): string[] {
        // Node.js crypto uses OpenSSL under the hood
        return crypto.getCiphers();
    }

    useNodeForge(): any {
        const forge = require('node-forge');
        const md = forge.md.sha256.create();
        return md;
    }

    async useWebCrypto(): Promise<CryptoKey> {
        const { webcrypto } = require('crypto');
        const subtle = webcrypto.subtle;
        return await subtle.generateKey(
            { name: 'AES-GCM', length: 256 },
            true,
            ['encrypt', 'decrypt']
        );
    }

    useSodiumNative(): Buffer {
        const sodium = require('sodium-native');
        const key = Buffer.alloc(sodium.crypto_secretbox_KEYBYTES);
        sodium.randombytes_buf(key);
        return key;
    }
}

export {
    CryptoService,
    AesCipher,
    LibraryUsage,
    CryptoResult
};
