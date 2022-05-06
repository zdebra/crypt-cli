package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEncrypt(t *testing.T) {
	t.Run("encrypt-decrypt 16 chars", func(t *testing.T) {
		password := "xx"
		text := "This is a secret"
		encrypted, err := Encrypt(password, text)
		assert.NoError(t, err)
		decrypted, err := Decrypt(password, encrypted)
		assert.NoError(t, err)
		assert.Equal(t, text, decrypted)
	})
	t.Run("encrypt-decrypt long text", func(t *testing.T) {
		password := "xx"
		text := ` Lorem ipsum dolor sit amet, consectetuer adipiscing elit. In sem justo, commodo ut, suscipit at, pharetra vitae, orci. Aliquam erat volutpat. Lorem ipsum dolor sit amet, consectetuer adipiscing elit. Phasellus enim erat, vestibulum vel, aliquam a, posuere eu, velit. Mauris elementum mauris vitae tortor. Integer vulputate sem a nibh rutrum consequat. Vivamus ac leo pretium faucibus. Quisque porta. Aliquam erat volutpat. Pellentesque habitant morbi tristique senectus et netus et malesuada fames ac turpis egestas. In sem justo, commodo ut, suscipit at, pharetra vitae, orci. Pellentesque habitant morbi tristique senectus et netus et malesuada fames ac turpis egestas. Vivamus porttitor turpis ac leo. Sed convallis magna eu sem. Etiam dui sem, fermentum vitae, sagittis id, malesuada in, quam. Aliquam in lorem sit amet leo accumsan lacinia. Neque porro quisquam est, qui dolorem ipsum quia dolor sit amet, consectetur, adipisci velit, sed quia non numquam eius modi tempora incidunt ut labore et dolore magnam aliquam quaerat voluptatem. Lorem ipsum dolor sit amet, consectetuer adipiscing elit.`
		encrypted, err := Encrypt(password, text)
		assert.NoError(t, err)
		decrypted, err := Decrypt(password, encrypted)
		assert.NoError(t, err)
		assert.Equal(t, text, decrypted)
	})
	t.Run("encrypt-decrypt short text", func(t *testing.T) {
		password := "xx"
		text := `abcde`
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
