package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"fmt"
)

var (
	initialVector = "1234567890123456"
)

func Encrypt(password, plaintext string) (string, error) {
	sanitizedPw, err := passwordSanity(password)
	if err != nil {
		return "", fmt.Errorf("password sanity check: %w", err)
	}
	block, err := aes.NewCipher([]byte(sanitizedPw))
	if err != nil {
		return "", fmt.Errorf("create AES cipher: %w", err)
	}
	cbc := cipher.NewCBCEncrypter(block, []byte(initialVector))

	textPadded := pkcs7pad([]byte(plaintext), block.BlockSize())
	out := make([]byte, len(textPadded))
	cbc.CryptBlocks(out, textPadded)
	return hex.EncodeToString(out), nil
}

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
	cbc := cipher.NewCBCDecrypter(block, []byte(initialVector))

	plaintext := make([]byte, len(ciphertext))
	cbc.CryptBlocks(plaintext, ciphertext)
	return string(pkcs7strip(plaintext, block.BlockSize())), nil
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

func pkcs7strip(data []byte, blockSize int) []byte {
	length := len(data)
	if length == 0 {
		panic("data is empty")
	}
	if length%blockSize != 0 {
		panic("data is not block-aligned")
	}
	padLen := int(data[length-1])
	ref := bytes.Repeat([]byte{byte(padLen)}, padLen)
	if padLen > blockSize || padLen == 0 || !bytes.HasSuffix(data, ref) {
		panic("invalid padding")
	}
	return data[:length-padLen]
}

func pkcs7pad(data []byte, blockSize int) []byte {
	if blockSize < 0 || blockSize > 256 {
		panic("invalid block size")
	}
	padLen := blockSize - len(data)%blockSize
	padding := bytes.Repeat([]byte{byte(padLen)}, padLen)
	return append(data, padding...)
}
