package main

import (
	"bytes"
	"crypto/aes"
	"encoding/hex"
	"fmt"
)

func Encrypt(password, plaintext string) (string, error) {
	sanitizedPw, err := passwordSanity(password)
	if err != nil {
		return "", fmt.Errorf("password sanity check: %w", err)
	}
	cipher, err := aes.NewCipher([]byte(sanitizedPw))
	if err != nil {
		return "", fmt.Errorf("create AES cipher: %w", err)
	}
	out := make([]byte, len(plaintext))

	cipher.Encrypt(out, []byte(plaintext))
	return hex.EncodeToString(out), nil
}

func Decrypt(password, encryptedTextHex string) (string, error) {
	sanitizedPw, err := passwordSanity(password)
	if err != nil {
		return "", fmt.Errorf("password sanity check: %w", err)
	}
	ciphertext, _ := hex.DecodeString(encryptedTextHex)
	cipher, err := aes.NewCipher([]byte(sanitizedPw))
	if err != nil {
		return "", fmt.Errorf("create AES cipher: %w", err)
	}

	plaintext := make([]byte, len(ciphertext))
	cipher.Decrypt(plaintext, ciphertext)
	return string(plaintext), nil
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
	return fmt.Sprintf("%0*s", 32, pw), nil
}

func PKCS5Padding(src []byte, blockSize int) []byte {
	padding := blockSize - len(src)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(src, padtext...)
}

func PKCS5UnPadding(src []byte) []byte {
	length := len(src)
	unpadding := int(src[length-1])
	return src[:(length - unpadding)]
}
