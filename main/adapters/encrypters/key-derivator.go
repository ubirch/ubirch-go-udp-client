package encrypters

import (
	"crypto/sha256"
	"encoding/base64"
	"golang.org/x/crypto/pbkdf2"
	"hash"
)

type KeyDerivator struct {
	salt     []byte
	iter     int
	keyLen   int
	hashFunc func() hash.Hash
}

func NewDefaultKeyDerivator(salt []byte) *KeyDerivator {
	return &KeyDerivator{
		salt:     salt,
		iter:     10000,
		keyLen:   32,
		hashFunc: sha256.New,
	}
}

// GetDerivedKey derives a key from the password, salt and iteration count, based on PBKDF2
// with the HMAC variant using the supplied hash function and returns the base64 encoded key of length keylen.
func (kd *KeyDerivator) GetDerivedKey(password string) string {
	return base64.StdEncoding.EncodeToString(pbkdf2.Key([]byte(password), kd.salt, kd.iter, kd.keyLen, kd.hashFunc))
}
