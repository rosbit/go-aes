package goaes

import (
	"testing"
	"fmt"
)

func TestWithShortKey(t *testing.T) {
	key := []byte("test")
	_, err := AesEncrypt([]byte("hello"), key)
	if err == nil {
		t.Errorf("there should be error\n")
		return
	}
	fmt.Printf("test with short key ok\n")
}

func TestAes(t *testing.T) {
	key := []byte("this is valid key, at least 16 bytes")
	oriText := "message to be encrypted"
	crypted, err := AesEncrypt([]byte(oriText), key)
	if err != nil {
		t.Errorf("failed to crypt: %v\n", err)
		return
	}
	decrypted, err := AesDecrypt(crypted, key)
	if err != nil {
		t.Errorf("failed to decrypt: %v\n", err)
		return
	}
	if oriText != string(decrypted) {
		t.Errorf("decrypted string is not same as oriText")
		return
	}
	fmt.Printf("test aes ok\n")
}
