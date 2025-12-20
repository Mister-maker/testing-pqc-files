// Quantum Safe - Hybrid PQC Implementations
package pqc;

import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.bouncycastle.pqc.jcajce.spec.KyberParameterSpec;
import org.bouncycastle.crypto.generators.HKDFBytesGenerator;
import org.bouncycastle.crypto.params.HKDFParameters;
import org.bouncycastle.crypto.digests.SHA256Digest;
import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.NamedParameterSpec;
import javax.crypto.KEM;
import javax.crypto.KeyAgreement;

public class HybridPqc {

    static {
        Security.addProvider(new BouncyCastlePQCProvider());
    }

    // Hybrid X25519 + Kyber768
    public byte[] hybridX25519Kyber768() throws Exception {
        // Classical X25519
        KeyPairGenerator x25519Gen = KeyPairGenerator.getInstance("X25519");
        KeyPair x25519KeyPair = x25519Gen.generateKeyPair();

        KeyAgreement x25519Agreement = KeyAgreement.getInstance("X25519");
        x25519Agreement.init(x25519KeyPair.getPrivate());
        x25519Agreement.doPhase(x25519KeyPair.getPublic(), true);
        byte[] x25519Secret = x25519Agreement.generateSecret();

        // Post-quantum Kyber768
        KeyPairGenerator kyberGen = KeyPairGenerator.getInstance("Kyber", "BCPQC");
        kyberGen.initialize(KyberParameterSpec.kyber768);
        KeyPair kyberKeyPair = kyberGen.generateKeyPair();

        KEM kem = KEM.getInstance("Kyber");
        KEM.Encapsulator enc = kem.newEncapsulator(kyberKeyPair.getPublic());
        KEM.Encapsulated encapsulated = enc.encapsulate();
        byte[] kyberSecret = encapsulated.key().getEncoded();

        // Combine shared secrets with HKDF
        return combineSecrets(x25519Secret, kyberSecret);
    }

    public byte[] hybridEcdhMlKem() throws Exception {
        // ECDH + ML-KEM hybrid
        KeyPairGenerator ecGen = KeyPairGenerator.getInstance("EC");
        ecGen.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair ecKeyPair = ecGen.generateKeyPair();

        KeyAgreement ecdhAgreement = KeyAgreement.getInstance("ECDH");
        ecdhAgreement.init(ecKeyPair.getPrivate());

        // ML-KEM (Kyber)
        KeyPairGenerator kyberGen = KeyPairGenerator.getInstance("Kyber", "BCPQC");
        kyberGen.initialize(KyberParameterSpec.kyber768);
        KeyPair kyberKeyPair = kyberGen.generateKeyPair();

        KEM kem = KEM.getInstance("Kyber");
        KEM.Encapsulator enc = kem.newEncapsulator(kyberKeyPair.getPublic());
        KEM.Encapsulated result = enc.encapsulate();

        return result.key().getEncoded();
    }

    public void hybridTlsPqc() throws Exception {
        // Hybrid TLS with PQC - X25519Kyber768Draft00
        KeyPairGenerator x25519Gen = KeyPairGenerator.getInstance("XDH");
        x25519Gen.initialize(NamedParameterSpec.X25519);
        KeyPair x25519KeyPair = x25519Gen.generateKeyPair();

        KeyPairGenerator kyberGen = KeyPairGenerator.getInstance("Kyber", "BCPQC");
        kyberGen.initialize(KyberParameterSpec.kyber768);
        KeyPair kyberKeyPair = kyberGen.generateKeyPair();
    }

    public void x25519Kyber768Draft00() throws Exception {
        // IETF draft hybrid key exchange
        KeyPairGenerator x25519Gen = KeyPairGenerator.getInstance("X25519");
        KeyPair x25519Keys = x25519Gen.generateKeyPair();

        KeyPairGenerator kyberGen = KeyPairGenerator.getInstance("Kyber", "BCPQC");
        kyberGen.initialize(KyberParameterSpec.kyber768);
        KeyPair kyberKeys = kyberGen.generateKeyPair();
    }

    public byte[] ecdhKyberComposite() throws Exception {
        // Composite key encapsulation
        KeyPairGenerator ecGen = KeyPairGenerator.getInstance("EC");
        ecGen.initialize(new ECGenParameterSpec("secp384r1"));
        KeyPair ecKeyPair = ecGen.generateKeyPair();

        KeyPairGenerator kyberGen = KeyPairGenerator.getInstance("Kyber", "BCPQC");
        kyberGen.initialize(KyberParameterSpec.kyber768);
        KeyPair kyberKeyPair = kyberGen.generateKeyPair();

        KEM kem = KEM.getInstance("Kyber");
        KEM.Encapsulator enc = kem.newEncapsulator(kyberKeyPair.getPublic());
        KEM.Encapsulated result = enc.encapsulate();

        return result.key().getEncoded();
    }

    private byte[] combineSecrets(byte[] secret1, byte[] secret2) {
        byte[] combined = new byte[secret1.length + secret2.length];
        System.arraycopy(secret1, 0, combined, 0, secret1.length);
        System.arraycopy(secret2, 0, combined, secret1.length, secret2.length);

        HKDFBytesGenerator hkdf = new HKDFBytesGenerator(new SHA256Digest());
        hkdf.init(new HKDFParameters(combined, null, "hybrid-kem".getBytes()));
        byte[] result = new byte[32];
        hkdf.generateBytes(result, 0, 32);
        return result;
    }
}
