// Quantum Vulnerable - Broken/Weak Algorithms (DO NOT USE IN PRODUCTION)
package pqc

import (
	"crypto/des"
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"

	"golang.org/x/crypto/blowfish"
	"golang.org/x/crypto/ripemd160"
	"golang.org/x/crypto/curve25519"
)

// Broken Hash (VULNERABLE)
func MD5BrokenHash() {
	hash := md5.Sum([]byte("insecure data"))
	_ = hash
}

func MD4BrokenHash() {
	// MD4 is even more broken than MD5
	hasher := md5.New() // Using md5 as placeholder
	hasher.Write([]byte("md4 is broken"))
	_ = hasher.Sum(nil)
}

func SHA1BrokenHash() {
	hash := sha1.Sum([]byte("sha1 collision attacks"))
	_ = hash
}

func RIPEMDWeakHash() {
	hasher := ripemd160.New()
	hasher.Write([]byte("ripemd data"))
	hash := hasher.Sum(nil)
	_ = hash
}

// Weak Symmetric (VULNERABLE)
func DESWeakCipher() {
	key := []byte("8bytkey") // DES uses 8-byte keys
	block, _ := des.NewCipher(key)
	_ = block
}

func TripleDES3DESCipher() {
	key := make([]byte, 24) // 3DES uses 24-byte keys
	block, _ := des.NewTripleDESCipher(key)
	_ = block
}

func BlowfishCipher() {
	key := []byte("secret key")
	cipher, _ := blowfish.NewCipher(key)
	_ = cipher
}

func RC4StreamCipher() {
	// RC4 is completely broken - don't use
	// Using placeholder as rc4 is deprecated
	key := []byte("rc4 key")
	_ = key
}

// Shor Vulnerable - Asymmetric (VULNERABLE to quantum computers)
func RSAEncryption() {
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	publicKey := &privateKey.PublicKey

	ciphertext, _ := rsa.EncryptPKCS1v15(rand.Reader, publicKey, []byte("data"))
	_ = ciphertext
}

func DSASignature() {
	var params dsa.Parameters
	dsa.GenerateParameters(&params, rand.Reader, dsa.L2048N256)

	var privateKey dsa.PrivateKey
	privateKey.Parameters = params
	dsa.GenerateKey(&privateKey, rand.Reader)
}

func ECDSASignature() {
	privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	message := []byte("message to sign")
	hash := sha256.Sum256(message)
	r, s, _ := ecdsa.Sign(rand.Reader, privateKey, hash[:])
	_ = r
	_ = s
}

func DiffieHellmanKeyExchange() {
	var privateKey [32]byte
	rand.Read(privateKey[:])
	var publicKey [32]byte
	curve25519.ScalarBaseMult(&publicKey, &privateKey)
}

func ECDHKeyExchange() {
	privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	// ECDH would use the private key for key agreement
	_ = privateKey.PublicKey
}

// Vulnerable Curves
func Secp256k1Curve() {
	// secp256k1 - used in Bitcoin
	privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	_ = privateKey
}

func P384Curve() {
	privateKey, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	_ = privateKey
}

func P521Curve() {
	privateKey, _ := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	_ = privateKey
}

func Curve25519Key() {
	var privateKey [32]byte
	rand.Read(privateKey[:])
	var publicKey [32]byte
	curve25519.ScalarBaseMult(&publicKey, &privateKey)
}

func Ed25519Signature() {
	// Ed25519 - vulnerable to Shor's algorithm
	import "crypto/ed25519"
	publicKey, privateKey, _ := ed25519.GenerateKey(rand.Reader)
	signature := ed25519.Sign(privateKey, []byte("message"))
	_ = publicKey
	_ = signature
}
