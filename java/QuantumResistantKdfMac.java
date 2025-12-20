// Quantum Resistant - KDF and MAC
package pqc;

import javax.crypto.Mac;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.crypto.generators.*;
import org.bouncycastle.crypto.params.*;
import org.bouncycastle.crypto.macs.Poly1305;
import org.bouncycastle.crypto.digests.SHA256Digest;

public class QuantumResistantKdfMac {

    // KDF Functions
    public byte[] hkdfDerive(byte[] ikm, byte[] salt, byte[] info, int length) {
        HKDFBytesGenerator hkdf = new HKDFBytesGenerator(new SHA256Digest());
        HKDFParameters params = new HKDFParameters(ikm, salt, info);
        hkdf.init(params);
        byte[] okm = new byte[length];
        hkdf.generateBytes(okm, 0, length);
        return okm;
    }

    public byte[] pbkdf2Derive(char[] password, byte[] salt, int iterations, int keyLength) throws Exception {
        PBEKeySpec spec = new PBEKeySpec(password, salt, iterations, keyLength * 8);
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        return factory.generateSecret(spec).getEncoded();
    }

    public byte[] argon2Derive(byte[] password, byte[] salt, int iterations, int memory, int parallelism, int keyLength) {
        Argon2BytesGenerator generator = new Argon2BytesGenerator();
        Argon2Parameters.Builder builder = new Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
            .withSalt(salt)
            .withIterations(iterations)
            .withMemoryAsKB(memory)
            .withParallelism(parallelism);
        generator.init(builder.build());
        byte[] result = new byte[keyLength];
        generator.generateBytes(password, result);
        return result;
    }

    public byte[] scryptDerive(byte[] password, byte[] salt, int n, int r, int p, int keyLength) {
        return SCrypt.generate(password, salt, n, r, p, keyLength);
    }

    public String bcryptHash(char[] password) {
        return BCrypt.generate(new String(password).getBytes(),
            new byte[16], 12).toString();
    }

    // MAC Functions
    public byte[] hmacSha256Mac(byte[] key, byte[] message) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        SecretKeySpec secretKey = new SecretKeySpec(key, "HmacSHA256");
        mac.init(secretKey);
        return mac.doFinal(message);
    }

    public byte[] hmacSha512Mac(byte[] key, byte[] message) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA512");
        SecretKeySpec secretKey = new SecretKeySpec(key, "HmacSHA512");
        mac.init(secretKey);
        return mac.doFinal(message);
    }

    public byte[] poly1305Mac(byte[] key, byte[] message) {
        Poly1305 poly = new Poly1305();
        poly.init(new KeyParameter(key));
        poly.update(message, 0, message.length);
        byte[] mac = new byte[16];
        poly.doFinal(mac, 0);
        return mac;
    }
}
