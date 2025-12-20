// Quantum Safe - Digital Signatures
package pqc

import (
	"github.com/cloudflare/circl/sign/dilithium/mode2"
	"github.com/cloudflare/circl/sign/dilithium/mode3"
	"github.com/cloudflare/circl/sign/ed448"
	"github.com/open-quantum-safe/liboqs-go/oqs"
)

func MLDsa44Signature() {
	pk, sk, _ := mode2.GenerateKey(nil)
	message := []byte("quantum safe message")
	signature := mode2.Sign(sk, message)
	valid := mode2.Verify(pk, message, signature)
	_ = valid
}

func MLDsa65Example() {
	publicKey, secretKey, _ := mode3.GenerateKey(nil)
	sig := mode3.Sign(secretKey, []byte("test data"))
	_ = publicKey
	_ = sig
}

func Falcon512Signature() {
	signer := oqs.Signature{}
	signer.Init("Falcon-512", nil)
	pk, _ := signer.GenerateKeyPair()
	msg := []byte("falcon signed message")
	sig, _ := signer.Sign(msg)
	valid, _ := signer.Verify(msg, sig, pk)
	_ = valid
}

func SLHDsaSphincsPlus() {
	signer := oqs.Signature{}
	signer.Init("SPHINCS+-SHA256-128f-robust", nil)
	pk, _ := signer.GenerateKeyPair()
	signature, _ := signer.Sign([]byte("data"))
	_ = pk
	_ = signature
}

func DilithiumSignature() {
	scheme := mode3.Scheme()
	pk, sk, _ := scheme.GenerateKey()
	sig := scheme.Sign(sk, []byte("dilithium message"), nil)
	_ = pk
	_ = sig
}

func XMSSSignatureExample() {
	signer := oqs.Signature{}
	signer.Init("Dilithium2", nil)
	pk, _ := signer.GenerateKeyPair()
	signature, _ := signer.Sign([]byte("xmss message"))
	_ = pk
	_ = signature
}

func LMSHashBasedSignature() {
	// LMS - Leighton-Micali Signature
	signer := oqs.Signature{}
	signer.Init("Dilithium3", nil)
	_, _ = signer.GenerateKeyPair()
}
