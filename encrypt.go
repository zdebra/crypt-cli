package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"errors"
	"fmt"
)

var ErrInvalidPassword = errors.New("invalid password")

// Encrypt plaintext with a password
// password has to be at least non empty string with maximum length of 32
// plaintext is encrypted AES in CBC mode
func Encrypt(password, plaintext string) (string, error) {
	sanitizedPw, err := passwordSanity(password)
	if err != nil {
		return "", fmt.Errorf("password sanity check: %w", err)
	}
	block, err := aes.NewCipher([]byte(sanitizedPw))
	if err != nil {
		return "", fmt.Errorf("create AES cipher: %w", err)
	}
	cbc := cipher.NewCBCEncrypter(block, initialVector(block.BlockSize()))

	textPadded := pkcs7pad([]byte(plaintext), block.BlockSize())
	out := make([]byte, len(textPadded))
	cbc.CryptBlocks(out, textPadded)
	return hex.EncodeToString(out), nil
}

// Decrypt previously encrypted text with a password
func Decrypt(password, encryptedTextHex string) (string, error) {
	sanitizedPw, err := passwordSanity(password)
	if err != nil {
		return "", fmt.Errorf("password sanity check: %w", err)
	}
	ciphertext, _ := hex.DecodeString(encryptedTextHex)
	block, err := aes.NewCipher([]byte(sanitizedPw))
	if err != nil {
		return "", fmt.Errorf("create AES cipher: %w", err)
	}
	cbc := cipher.NewCBCDecrypter(block, initialVector(block.BlockSize()))

	plaintextWithPadding := make([]byte, len(ciphertext))
	cbc.CryptBlocks(plaintextWithPadding, ciphertext)
	plaintext, err := pkcs7strip(plaintextWithPadding, block.BlockSize())
	if err != nil {
		return "", ErrInvalidPassword
	}
	return string(plaintext), nil
}

func initialVector(size int) []byte {
	return bytes.Repeat([]byte{byte(size)}, size)
}

func passwordSanity(pw string) (string, error) {
	switch {
	case len(pw) > 32:
		return "", fmt.Errorf("password too long")
	case len(pw) == 32:
		return pw, nil
	case len(pw) == 0:
		return "", fmt.Errorf("no password")
	}
	return string(pkcs7pad([]byte(pw), 32)), nil
}

func pkcs7strip(data []byte, blockSize int) ([]byte, error) {
	length := len(data)
	if length == 0 {
		return nil, fmt.Errorf("data is empty")
	}
	if length%blockSize != 0 {
		return nil, fmt.Errorf("data is not block-aligned")
	}
	padLen := int(data[length-1])
	ref := bytes.Repeat([]byte{byte(padLen)}, padLen)
	if padLen > blockSize || padLen == 0 || !bytes.HasSuffix(data, ref) {
		return nil, fmt.Errorf("invalid padding")
	}
	return data[:length-padLen], nil
}

func pkcs7pad(data []byte, blockSize int) []byte {
	if blockSize < 0 || blockSize > 256 {
		panic("invalid block size")
	}
	padLen := blockSize - len(data)%blockSize
	padding := bytes.Repeat([]byte{byte(padLen)}, padLen)
	return append(data, padding...)
}
