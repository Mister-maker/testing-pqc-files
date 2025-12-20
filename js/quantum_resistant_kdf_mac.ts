// Quantum Resistant - KDF and MAC - TypeScript
import * as crypto from 'crypto';
import { hkdf } from '@noble/hashes/hkdf';
import { sha256 } from '@noble/hashes/sha256';
import { pbkdf2 } from '@noble/hashes/pbkdf2';
import * as argon2 from 'argon2';
import * as bcrypt from 'bcrypt';
import { poly1305 } from '@noble/ciphers/chacha';

interface KdfOptions {
    iterations?: number;
    keyLength?: number;
    salt?: Buffer;
}

// KDF Functions
class HkdfDerive {
    derive(ikm: Uint8Array, salt: Uint8Array, info: Uint8Array, length: number = 32): Uint8Array {
        return hkdf(sha256, ikm, salt, info, length);
    }

    deriveNode(secret: Buffer, salt: Buffer, info: Buffer, length: number = 32): Buffer {
        return crypto.hkdfSync('sha256', secret, salt, info, length);
    }
}

class Pbkdf2Derive {
    derive(password: Uint8Array, salt: Uint8Array, options: KdfOptions = {}): Uint8Array {
        const iterations = options.iterations || 100000;
        const keyLength = options.keyLength || 32;
        return pbkdf2(sha256, password, salt, { c: iterations, dkLen: keyLength });
    }

    deriveNode(password: string, salt: Buffer, options: KdfOptions = {}): Buffer {
        const iterations = options.iterations || 100000;
        const keyLength = options.keyLength || 32;
        return crypto.pbkdf2Sync(password, salt, iterations, keyLength, 'sha256');
    }
}

class Argon2Derive {
    async hash(password: string, salt?: Buffer): Promise<string> {
        return await argon2.hash(password, {
            type: argon2.argon2id,
            memoryCost: 65536,
            timeCost: 3,
            parallelism: 4,
            salt: salt
        });
    }

    async verify(hash: string, password: string): Promise<boolean> {
        return await argon2.verify(hash, password);
    }
}

class ScryptDerive {
    derive(password: Buffer, salt: Buffer, keyLength: number = 32): Buffer {
        return crypto.scryptSync(password, salt, keyLength, {
            N: 16384,
            r: 8,
            p: 1
        });
    }
}

class BcryptHash {
    async hash(password: string, rounds: number = 12): Promise<string> {
        return await bcrypt.hash(password, rounds);
    }

    async verify(password: string, hash: string): Promise<boolean> {
        return await bcrypt.compare(password, hash);
    }
}

// MAC Functions
class HmacSha256Mac {
    mac(key: Buffer, message: Buffer): Buffer {
        return crypto.createHmac('sha256', key).update(message).digest();
    }
}

class HmacSha512Mac {
    mac(key: Buffer, message: Buffer): Buffer {
        return crypto.createHmac('sha512', key).update(message).digest();
    }
}

class Poly1305Mac {
    mac(key: Uint8Array, message: Uint8Array): Uint8Array {
        return poly1305(key, message);
    }
}

export {
    HkdfDerive,
    Pbkdf2Derive,
    Argon2Derive,
    ScryptDerive,
    BcryptHash,
    HmacSha256Mac,
    HmacSha512Mac,
    Poly1305Mac,
    KdfOptions
};
