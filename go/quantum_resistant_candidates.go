// Quantum Resistant - PQC Candidates (KEM and Signatures)
package pqc

import (
	"github.com/open-quantum-safe/liboqs-go/oqs"
)

// PQC Candidate KEMs
func NTRUKemExample() {
	kem := oqs.KeyEncapsulation{}
	kem.Init("NTRU-HPS-2048-509", nil)
	pk, _ := kem.GenerateKeyPair()
	ct, ss, _ := kem.Encapsulate(pk)
	decrypted, _ := kem.Decapsulate(ct)
	_ = ss
	_ = decrypted
}

func ClassicMcElieceKem() {
	kem := oqs.KeyEncapsulation{}
	kem.Init("Classic-McEliece-348864", nil)
	pk, _ := kem.GenerateKeyPair()
	ciphertext, sharedSecret, _ := kem.Encapsulate(pk)
	_ = ciphertext
	_ = sharedSecret
}

func HQCKemExample() {
	kem := oqs.KeyEncapsulation{}
	kem.Init("HQC-128", nil)
	pk, _ := kem.GenerateKeyPair()
	ct, ss, _ := kem.Encapsulate(pk)
	_ = ct
	_ = ss
}

func BIKEKemExample() {
	kem := oqs.KeyEncapsulation{}
	kem.Init("BIKE-L1", nil)
	pk, _ := kem.GenerateKeyPair()
	ct, ss, _ := kem.Encapsulate(pk)
	_ = ct
	_ = ss
}

func SIKEVulnerableKem() {
	// SIKE - Supersingular Isogeny Key Encapsulation (VULNERABLE - broken)
	kem := oqs.KeyEncapsulation{}
	kem.Init("SIKE-p434", nil)
	pk, _ := kem.GenerateKeyPair()
	_ = pk
}

// PQC Candidate Signatures
func PicnicSignature() {
	signer := oqs.Signature{}
	signer.Init("Picnic-L1-full", nil)
	pk, _ := signer.GenerateKeyPair()
	sig, _ := signer.Sign([]byte("picnic message"))
	_ = pk
	_ = sig
}

func RainbowVulnerableSignature() {
	// Rainbow signature scheme (VULNERABLE - broken)
	signer := oqs.Signature{}
	signer.Init("Rainbow-I-Classic", nil)
	pk, _ := signer.GenerateKeyPair()
	_ = pk
}

func GeMSSSignatureExample() {
	// GeMSS - Great Multivariate Signature Scheme
	signer := oqs.Signature{}
	signer.Init("GeMSS-128", nil)
	_, _ = signer.GenerateKeyPair()
}
