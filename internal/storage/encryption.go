package storage

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
)

type EncryptedPayload struct {
	Nonce      []byte
	AuthTag    []byte
	Ciphertext []byte
}

func Encrypt(plaintext []byte, key [32]byte) (EncryptedPayload, error) {
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return EncryptedPayload{}, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return EncryptedPayload{}, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return EncryptedPayload{}, err
	}
	sealed := aead.Seal(nil, nonce, plaintext, nil)
	ciphertext := sealed[:len(sealed)-aead.Overhead()]
	authTag := sealed[len(sealed)-aead.Overhead():]

	return EncryptedPayload{
		Nonce:      nonce,
		AuthTag:    authTag,
		Ciphertext: ciphertext,
	}, nil
}

func Decrypt(payload EncryptedPayload, key [32]byte) ([]byte, error) {
	if len(payload.Nonce) != 12 || len(payload.AuthTag) != 16 {
		return nil, errors.New("wrong Nonce size or AuthTag size")
	}

	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	//safely append without occasionally overwriting the backing array of the original slice in unexpected ways
	ciphertext := make([]byte, 0, len(payload.Ciphertext)+len(payload.AuthTag))
	ciphertext = append(ciphertext, payload.Ciphertext...)
	ciphertext = append(ciphertext, payload.AuthTag...)

	plaintext, err := aesgcm.Open(nil, payload.Nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}
