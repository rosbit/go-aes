# go-aes
encrypt/decrypt message with AES

## Usage

```go
package main

import (
	"github.com/rosbit/go-aes"
	"fmt"
)

func main() {
	key := []byte("you key at least 16 bytes")
	oriText := "message to be encrypted"

	// encrypt
	crypted, err := goaes.AesEncrypt([]byte(oriText), key)
	if err != nil {
		fmt.Printf("failed to crypt: %v\n", err)
		return
	}

	// decrypt
	decrypted, err := goaes.AesDecrypt(crypted, key)
	if err != nil {
		fmt.Printf("failed to decrypt: %v\n", err)
		return
	}

	if oriText != string(decrypted) {
		fmt.Printf("decrypted string is not same as oriText")
		return
	}
	fmt.Printf("test aes ok\n")
}
```

## Status
The package is fully tested.

## Contribution
Pull requests are welcome! Also, if you want to discuss something send a pull request with proposal and changes.

