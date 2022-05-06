package main

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
)

var encryptCmd = &cobra.Command{
	Use:   "encrypt",
	Short: "Encrypt text with password",
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Println(args)
		if len(args) < 1 {
			return fmt.Errorf("no text to encrypt provided")
		}
		plaintext := strings.Join(args, " ")
		reader := bufio.NewReader(os.Stdin)
		fmt.Print("Enter password: ")
		password, _ := reader.ReadString('\n')

		encrypted, err := Encrypt(password, plaintext)
		if err != nil {
			return err
		}

		fmt.Println("Encrypted message:", encrypted)
		return nil
	},
}

var decryptCmd = &cobra.Command{
	Use:   "decrypt",
	Short: "Decrypt text with password",
	RunE: func(cmd *cobra.Command, args []string) error {
		if len(args) != 1 {
			return fmt.Errorf("no text to decrypt provided")
		}
		encrypted := strings.Join(args, " ")

		for {
			reader := bufio.NewReader(os.Stdin)
			fmt.Print("Enter password: ")
			password, _ := reader.ReadString('\n')

			plaintext, err := Decrypt(password, encrypted)
			if errors.Is(err, ErrInvalidPassword) {
				fmt.Println("invalid password")
				continue
			}
			if err != nil {
				return err
			}
			fmt.Println("Decrypted message:", plaintext)
			return nil
		}
	},
}

func main() {
	var rootCmd = &cobra.Command{Use: "app"}
	rootCmd.AddCommand(encryptCmd, decryptCmd)
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
