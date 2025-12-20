// Quantum Resistant - Strong Symmetric Encryption and Hashes
package pqc;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.MessageDigest;
import java.security.SecureRandom;
import org.bouncycastle.crypto.digests.*;
import org.bouncycastle.crypto.engines.ChaCha20Poly1305;

public class QuantumResistantSymmetric {

    // Strong Symmetric (256-bit)
    public byte[] aes256GcmEncryption(byte[] plaintext, byte[] key) throws Exception {
        SecretKeySpec secretKey = new SecretKeySpec(key, "AES");
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        byte[] iv = new byte[12];
        new SecureRandom().nextBytes(iv);
        GCMParameterSpec gcmSpec = new GCMParameterSpec(128, iv);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, gcmSpec);
        return cipher.doFinal(plaintext);
    }

    public byte[] chacha20Poly1305Encryption(byte[] plaintext, byte[] key) throws Exception {
        Cipher cipher = Cipher.getInstance("ChaCha20-Poly1305");
        SecretKeySpec secretKey = new SecretKeySpec(key, "ChaCha20");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        return cipher.doFinal(plaintext);
    }

    // Strong Symmetric (192-bit)
    public byte[] aes192Encryption(byte[] plaintext, byte[] key) throws Exception {
        SecretKeySpec secretKey = new SecretKeySpec(key, "AES");
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        byte[] iv = new byte[12];
        new SecureRandom().nextBytes(iv);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, new GCMParameterSpec(128, iv));
        return cipher.doFinal(plaintext);
    }

    // Strong Hash (512-bit)
    public byte[] sha512Hash(byte[] data) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-512");
        return md.digest(data);
    }

    public byte[] sha3_512Hash(byte[] data) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA3-512");
        return md.digest(data);
    }

    // Strong Hash (384-bit)
    public byte[] sha384Hash(byte[] data) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-384");
        return md.digest(data);
    }

    public byte[] sha3_384Hash(byte[] data) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA3-384");
        return md.digest(data);
    }

    // Strong Hash (256-bit)
    public byte[] sha256Hash(byte[] data) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        return md.digest(data);
    }

    public byte[] sha3_256Hash(byte[] data) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA3-256");
        return md.digest(data);
    }

    public byte[] blake3Hash(byte[] data) {
        Blake3Digest digest = new Blake3Digest(256);
        digest.update(data, 0, data.length);
        byte[] hash = new byte[32];
        digest.doFinal(hash, 0);
        return hash;
    }

    // Strong Hash (Variable - XOF)
    public byte[] shake128Xof(byte[] data, int outputLength) {
        SHAKEDigest shake = new SHAKEDigest(128);
        shake.update(data, 0, data.length);
        byte[] output = new byte[outputLength];
        shake.doFinal(output, 0, outputLength);
        return output;
    }

    public byte[] shake256Xof(byte[] data, int outputLength) {
        SHAKEDigest shake = new SHAKEDigest(256);
        shake.update(data, 0, data.length);
        byte[] output = new byte[outputLength];
        shake.doFinal(output, 0, outputLength);
        return output;
    }

    public byte[] blake2bHash(byte[] data) {
        Blake2bDigest digest = new Blake2bDigest(512);
        digest.update(data, 0, data.length);
        byte[] hash = new byte[64];
        digest.doFinal(hash, 0);
        return hash;
    }
}
