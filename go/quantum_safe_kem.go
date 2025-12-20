// Quantum Safe - Key Encapsulation Mechanisms (KEM)
package pqc

import (
	"github.com/cloudflare/circl/kem/kyber/kyber768"
	"github.com/cloudflare/circl/kem/kyber/kyber1024"
	"github.com/cloudflare/circl/kem/frodo/frodo640shake"
	"github.com/open-quantum-safe/liboqs-go/oqs"
)

func MLKem768Encapsulation() {
	pk, sk, _ := kyber768.GenerateKeyPair(nil)
	ct, ss, _ := kyber768.Encapsulate(pk)
	ssDecap, _ := kyber768.Decapsulate(sk, ct)
	_ = ssDecap
}

func MLKem1024Example() {
	publicKey, secretKey, _ := kyber1024.GenerateKeyPair(nil)
	ciphertext, sharedSecret, _ := kyber1024.Encapsulate(publicKey)
	decrypted, _ := kyber1024.Decapsulate(secretKey, ciphertext)
	_ = decrypted
	_ = sharedSecret
}

func FrodoKEMExample() {
	pk, sk, _ := frodo640shake.GenerateKeyPair(nil)
	ct, ss, _ := frodo640shake.Encapsulate(pk)
	_ = ss
	_ = ct
	_ = sk
}

func OqsMLKem512() {
	kem := oqs.KeyEncapsulation{}
	kem.Init("Kyber512", nil)
	pk, _ := kem.GenerateKeyPair()
	ct, ss, _ := kem.Encapsulate(pk)
	_ = ct
	_ = ss
}

func KyberKeyGeneration() {
	scheme := kyber768.Scheme()
	pk, sk, _ := scheme.GenerateKeyPair()
	_ = pk
	_ = sk
}
