package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEncrypt(t *testing.T) {
	t.Run("encrypt-decrypt", func(t *testing.T) {
		password := "xx"
		text := "This is a secret"
		encrypted, err := Encrypt(password, text)
		assert.NoError(t, err)
		decrypted, err := Decrypt(password, encrypted)
		assert.NoError(t, err)
		assert.Equal(t, text, decrypted)
	})
}

func TestPasswordSanity(t *testing.T) {
	t.Run("no pass", func(t *testing.T) {
		_, err := passwordSanity("")
		assert.Error(t, err)
	})
	t.Run("password < 32", func(t *testing.T) {
		pw, err := passwordSanity("xx")
		assert.NoError(t, err)
		assert.Equal(t, 32, len(pw))
		assert.Equal(t, "000000000000000000000000000000xx", pw)
	})
	t.Run("password len 32", func(t *testing.T) {
		plainpw := "tb0000dx0000000erx0000dsx00000xx"
		pw, err := passwordSanity(plainpw)
		assert.NoError(t, err)
		assert.Equal(t, 32, len(pw))
		assert.Equal(t, plainpw, pw)
	})
	t.Run("password > 32", func(t *testing.T) {
		plainpw := "tb0000dx0000000erx0000dsx00000xxasdasdasdas"
		_, err := passwordSanity(plainpw)
		assert.Error(t, err)
	})
}
