# crypt-cli

# Usage

```
Usage:
  cryptcli [command]

Available Commands:
  completion  Generate the autocompletion script for the specified shell
  decrypt     Decrypt text with password
  encrypt     Encrypt text with password
  help        Help about any command

Flags:
  -h, --help   help for app

Use "app [command] --help" for more information about a command.

```

## Example usage

```sh
$ go run . encrypt ahoj jak se mas ja se mam dobre co delas
Enter password: 1234
Encrypted message: 91b3b78ac4e462fd8a3f70436df76cb902a6247e32870e2e3ccaebbf2a32f443275379b9f3cb58e3b707645c56aecec5
$ go run . decrypt 91b3b78ac4e462fd8a3f70436df76cb902a6247e32870e2e3ccaebbf2a32f443275379b9f3cb58e3b707645c56aecec5
Enter password: wrong
invalid password
Enter password: password
invalid password
Enter password: 1234
Decrypted message: ahoj jak se mas ja se mam dobre co delas

```
