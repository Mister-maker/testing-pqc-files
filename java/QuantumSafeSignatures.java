// Quantum Safe - Digital Signatures
package pqc;

import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.bouncycastle.pqc.jcajce.spec.DilithiumParameterSpec;
import org.bouncycastle.pqc.jcajce.spec.FalconParameterSpec;
import org.bouncycastle.pqc.jcajce.spec.SPHINCSPlusParameterSpec;
import java.security.*;

public class QuantumSafeSignatures {

    static {
        Security.addProvider(new BouncyCastlePQCProvider());
    }

    public void mlDsa44Signature() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("Dilithium", "BCPQC");
        kpg.initialize(DilithiumParameterSpec.dilithium2);
        KeyPair keyPair = kpg.generateKeyPair();

        Signature sig = Signature.getInstance("Dilithium", "BCPQC");
        sig.initSign(keyPair.getPrivate());
        sig.update("quantum safe message".getBytes());
        byte[] signature = sig.sign();

        sig.initVerify(keyPair.getPublic());
        sig.update("quantum safe message".getBytes());
        boolean valid = sig.verify(signature);
    }

    public void mlDsa65Example() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("Dilithium", "BCPQC");
        kpg.initialize(DilithiumParameterSpec.dilithium3);
        KeyPair keyPair = kpg.generateKeyPair();

        Signature sig = Signature.getInstance("DILITHIUM3", "BCPQC");
        sig.initSign(keyPair.getPrivate());
        sig.update("test data".getBytes());
        byte[] signature = sig.sign();
    }

    public void mlDsa87Signature() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("Dilithium", "BCPQC");
        kpg.initialize(DilithiumParameterSpec.dilithium5);
        KeyPair keyPair = kpg.generateKeyPair();
    }

    public void falcon512Signature() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("Falcon", "BCPQC");
        kpg.initialize(FalconParameterSpec.falcon512);
        KeyPair keyPair = kpg.generateKeyPair();

        Signature sig = Signature.getInstance("Falcon", "BCPQC");
        sig.initSign(keyPair.getPrivate());
        sig.update("falcon signed message".getBytes());
        byte[] signature = sig.sign();
    }

    public void slhDsaSphincsPlus() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("SPHINCSPlus", "BCPQC");
        kpg.initialize(SPHINCSPlusParameterSpec.sha2_128f);
        KeyPair keyPair = kpg.generateKeyPair();

        Signature sig = Signature.getInstance("SPHINCSPlus", "BCPQC");
        sig.initSign(keyPair.getPrivate());
        sig.update("sphincs data".getBytes());
        byte[] signature = sig.sign();
    }

    public void xmssSignatureExample() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("XMSS", "BCPQC");
        KeyPair keyPair = kpg.generateKeyPair();

        Signature sig = Signature.getInstance("XMSS", "BCPQC");
        sig.initSign(keyPair.getPrivate());
        sig.update("xmss message".getBytes());
        byte[] signature = sig.sign();
    }

    public void lmsHashBasedSignature() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("LMS", "BCPQC");
        KeyPair keyPair = kpg.generateKeyPair();

        Signature sig = Signature.getInstance("LMS", "BCPQC");
        sig.initSign(keyPair.getPrivate());
        sig.update("lms message".getBytes());
        byte[] signature = sig.sign();
    }
}
