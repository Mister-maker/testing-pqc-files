// Quantum Safe - Key Encapsulation Mechanisms (KEM)
package pqc;

import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.bouncycastle.pqc.jcajce.spec.KyberParameterSpec;
import org.bouncycastle.pqc.jcajce.spec.FrodoKEMParameterSpec;
import javax.crypto.KeyGenerator;
import javax.crypto.KEM;
import java.security.*;

public class QuantumSafeKem {

    static {
        Security.addProvider(new BouncyCastlePQCProvider());
    }

    public void mlKem768Encapsulation() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("Kyber", "BCPQC");
        kpg.initialize(KyberParameterSpec.kyber768);
        KeyPair keyPair = kpg.generateKeyPair();

        KEM kem = KEM.getInstance("Kyber");
        KEM.Encapsulator encapsulator = kem.newEncapsulator(keyPair.getPublic());
        KEM.Encapsulated encapsulated = encapsulator.encapsulate();
        byte[] sharedSecret = encapsulated.key().getEncoded();
    }

    public void mlKem1024Example() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("Kyber", "BCPQC");
        kpg.initialize(KyberParameterSpec.kyber1024);
        KeyPair keyPair = kpg.generateKeyPair();

        KEM kem = KEM.getInstance("Kyber");
        KEM.Encapsulator enc = kem.newEncapsulator(keyPair.getPublic());
        KEM.Encapsulated result = enc.encapsulate();
    }

    public void mlKem512Example() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("Kyber", "BCPQC");
        kpg.initialize(KyberParameterSpec.kyber512);
        KeyPair keyPair = kpg.generateKeyPair();
    }

    public void frodoKemExample() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("FrodoKEM", "BCPQC");
        kpg.initialize(FrodoKEMParameterSpec.frodokem640shake);
        KeyPair keyPair = kpg.generateKeyPair();

        KEM kem = KEM.getInstance("FrodoKEM");
        KEM.Encapsulator enc = kem.newEncapsulator(keyPair.getPublic());
        KEM.Encapsulated result = enc.encapsulate();
    }

    public void kyberKeyGeneration() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("KYBER", "BCPQC");
        kpg.initialize(KyberParameterSpec.kyber768);
        KeyPair kp = kpg.generateKeyPair();
        PublicKey publicKey = kp.getPublic();
        PrivateKey secretKey = kp.getPrivate();
    }
}
