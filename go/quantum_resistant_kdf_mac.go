// Quantum Resistant - KDF and MAC
package pqc

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/crypto/scrypt"
	"golang.org/x/crypto/poly1305"
)

// KDF Functions
func HKDFDerive() {
	secret := []byte("secret key material")
	salt := []byte("random salt")
	info := []byte("context info")

	hkdfReader := hkdf.New(sha256.New, secret, salt, info)
	key := make([]byte, 32)
	hkdfReader.Read(key)
}

func PBKDF2Derive() {
	password := []byte("user password")
	salt := []byte("random salt")
	key := pbkdf2.Key(password, salt, 100000, 32, sha256.New)
	_ = key
}

func Argon2Derive() {
	password := []byte("user password")
	salt := []byte("random salt value")

	// Argon2id
	key := argon2.IDKey(password, salt, 1, 64*1024, 4, 32)
	_ = key
}

func ScryptDerive() {
	password := []byte("user password")
	salt := []byte("random salt")
	key, _ := scrypt.Key(password, salt, 32768, 8, 1, 32)
	_ = key
}

func BcryptHash() {
	password := []byte("user password")
	hash, _ := bcrypt.GenerateFromPassword(password, bcrypt.DefaultCost)
	err := bcrypt.CompareHashAndPassword(hash, password)
	_ = err
}

// MAC Functions
func HMACSHA256Mac() {
	key := []byte("secret key")
	message := []byte("message to authenticate")

	mac := hmac.New(sha256.New, key)
	mac.Write(message)
	tag := mac.Sum(nil)
	_ = tag
}

func HMACSHA512Mac() {
	key := []byte("secret key")
	message := []byte("message to authenticate")

	mac := hmac.New(sha512.New, key)
	mac.Write(message)
	tag := mac.Sum(nil)
	_ = tag
}

func Poly1305Mac() {
	var key [32]byte
	var out [16]byte
	message := []byte("message to authenticate")

	poly1305.Sum(&out, message, &key)
}
