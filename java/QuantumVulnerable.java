// Quantum Vulnerable - Broken/Weak Algorithms (DO NOT USE IN PRODUCTION)
package pqc;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.security.spec.ECGenParameterSpec;

public class QuantumVulnerable {

    // Broken Hash (VULNERABLE)
    public byte[] md5BrokenHash(byte[] data) throws Exception {
        MessageDigest md = MessageDigest.getInstance("MD5");
        return md.digest(data);
    }

    public byte[] md4BrokenHash(byte[] data) throws Exception {
        MessageDigest md = MessageDigest.getInstance("MD4");
        return md.digest(data);
    }

    public byte[] sha1BrokenHash(byte[] data) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-1");
        return md.digest(data);
    }

    public byte[] ripemdWeakHash(byte[] data) throws Exception {
        MessageDigest md = MessageDigest.getInstance("RIPEMD160");
        return md.digest(data);
    }

    // Weak Symmetric (VULNERABLE)
    public byte[] desWeakCipher(byte[] plaintext, byte[] key) throws Exception {
        SecretKeySpec secretKey = new SecretKeySpec(key, "DES");
        Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        return cipher.doFinal(plaintext);
    }

    public byte[] tripleDes3desCipher(byte[] plaintext, byte[] key) throws Exception {
        SecretKeySpec secretKey = new SecretKeySpec(key, "DESede");
        Cipher cipher = Cipher.getInstance("DESede/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        return cipher.doFinal(plaintext);
    }

    public byte[] rc4StreamCipher(byte[] plaintext, byte[] key) throws Exception {
        SecretKeySpec secretKey = new SecretKeySpec(key, "RC4");
        Cipher cipher = Cipher.getInstance("RC4");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        return cipher.doFinal(plaintext);
    }

    public byte[] blowfishCipher(byte[] plaintext, byte[] key) throws Exception {
        SecretKeySpec secretKey = new SecretKeySpec(key, "Blowfish");
        Cipher cipher = Cipher.getInstance("Blowfish/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        return cipher.doFinal(plaintext);
    }

    public byte[] ideaCipher(byte[] plaintext, byte[] key) throws Exception {
        SecretKeySpec secretKey = new SecretKeySpec(key, "IDEA");
        Cipher cipher = Cipher.getInstance("IDEA/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        return cipher.doFinal(plaintext);
    }

    // Weak MAC (VULNERABLE)
    public byte[] hmacMd5Weak(byte[] key, byte[] message) throws Exception {
        Mac mac = Mac.getInstance("HmacMD5");
        SecretKeySpec secretKey = new SecretKeySpec(key, "HmacMD5");
        mac.init(secretKey);
        return mac.doFinal(message);
    }

    public byte[] hmacSha1Weak(byte[] key, byte[] message) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA1");
        SecretKeySpec secretKey = new SecretKeySpec(key, "HmacSHA1");
        mac.init(secretKey);
        return mac.doFinal(message);
    }

    // Shor Vulnerable - Asymmetric (VULNERABLE to quantum computers)
    public KeyPair rsaEncryption() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair keyPair = kpg.generateKeyPair();

        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, keyPair.getPublic());
        return keyPair;
    }

    public KeyPair dsaSignature() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("DSA");
        kpg.initialize(2048);
        KeyPair keyPair = kpg.generateKeyPair();

        Signature sig = Signature.getInstance("SHA256withDSA");
        sig.initSign(keyPair.getPrivate());
        return keyPair;
    }

    public KeyPair ecdsaSignature() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair keyPair = kpg.generateKeyPair();

        Signature sig = Signature.getInstance("SHA256withECDSA");
        sig.initSign(keyPair.getPrivate());
        return keyPair;
    }

    public KeyPair diffieHellmanKeyExchange() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("DH");
        kpg.initialize(2048);
        return kpg.generateKeyPair();
    }

    public KeyPair ecdhKeyExchange() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(new ECGenParameterSpec("secp256r1"));
        return kpg.generateKeyPair();
    }

    // Vulnerable Curves
    public KeyPair secp256k1Curve() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(new ECGenParameterSpec("secp256k1"));
        return kpg.generateKeyPair();
    }

    public KeyPair p384Curve() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(new ECGenParameterSpec("secp384r1"));
        return kpg.generateKeyPair();
    }

    public KeyPair p521Curve() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(new ECGenParameterSpec("secp521r1"));
        return kpg.generateKeyPair();
    }

    public KeyPair ed25519Signature() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("Ed25519");
        return kpg.generateKeyPair();
    }
}
