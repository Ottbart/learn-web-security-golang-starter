package passwords

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"strings"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"
)

const (
	memoryKiB   = 19 * 1024
	iterations  = 2
	parallelism = 1
	MaxLength   = 128
	keyLength   = 32
	saltLength  = 16
)

func Hash(password string) (string, error) {
	if utf8.RuneCountInString(password) > MaxLength {
		return "", errors.New("password exceeds 128 character limit")
	}
	salt := make([]byte, saltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	derivedKey := argon2.IDKey([]byte(password), salt, iterations, memoryKiB, parallelism, keyLength)

	return encodeArgon2idHash(argon2idHash{
		version:     int(argon2.Version),
		memoryKiB:   memoryKiB,
		iterations:  iterations,
		parallelism: parallelism,
		salt:        salt,
		derivedKey:  derivedKey,
	}), nil
}

func Verify(password, encodedHash string) bool {
	if utf8.RuneCountInString(password) > MaxLength {
		return false
	}
	expectedHash, ok := decodeLegacyHash(encodedHash)
	if ok { //legacy hash

		candidateHash := sha256.Sum256([]byte(password))
		legacyHashOK := subtle.ConstantTimeCompare(candidateHash[:], expectedHash) == 1
		if legacyHashOK {
			return true
		} else {
			return false
		}
	}

	//argon2id
	if strings.HasPrefix(encodedHash, "$argon2id$") {
		argon2Hash, ok := parseArgon2idHash(encodedHash)
		if !ok {
			return false
		}
		if argon2Hash.version != argon2.Version {
			return false
		}

		derivedKey := argon2.IDKey([]byte(password), argon2Hash.salt, argon2Hash.iterations, argon2Hash.memoryKiB, argon2Hash.parallelism, keyLength)
		argon2ok := subtle.ConstantTimeCompare(derivedKey[:], argon2Hash.derivedKey) == 1
		if argon2ok {
			return true
		}
	}
	return false
}

func NeedsRehash(encodedHash string) bool {
	_, ok := decodeLegacyHash(encodedHash)
	if ok { //is legacy hash, needs rehash
		return true
	}

	argon2Hash, ok := parseArgon2idHash(encodedHash)
	if !ok {
		return false
	}
	//check all argon2id parameters
	if argon2Hash.version != argon2.Version ||
		argon2Hash.memoryKiB != memoryKiB ||
		argon2Hash.iterations != iterations ||
		argon2Hash.parallelism != parallelism {
		return true
	}
	return false
}
