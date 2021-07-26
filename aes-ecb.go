package goaes

import (
	"crypto/aes"
	"fmt"
)

func AesEncryptECB(plainText []byte, key []byte) ([]byte, error) {
	if plainText == nil {
		return nil, nil
	}

	realKey, err := adjustKey(key)
	if err != nil {
		return nil, err
	}
	aesBlk, _ := aes.NewCipher(realKey)
	blockSize := aesBlk.BlockSize()
	paddedPlainText := _PKCS5Padding(plainText, blockSize)
	crypted := make([]byte, len(paddedPlainText))

	for bs, be := 0, blockSize; bs <= len(plainText); bs, be = bs + blockSize, be + blockSize {
		aesBlk.Encrypt(crypted[bs:be], paddedPlainText[bs:be])
	}

	return crypted, nil
}

func AesDecryptECB(cryptedText []byte, key []byte) (b []byte, e error) {
	if cryptedText == nil {
		return nil, nil
	}

	realKey, err := adjustKey(key)
	if err != nil {
		return nil, err
	}

	defer func() {
		if r := recover(); r != nil {
			var ok bool
			if e, ok = r.(error); ok {
				return
			}
			e = fmt.Errorf("panic %v", r)
		}
	}()
	aesBlk, _ := aes.NewCipher(realKey)
	blockSize := aesBlk.BlockSize()
	plainText := make([]byte, len(cryptedText))
	for bs, be := 0, blockSize; bs < len(cryptedText); bs, be = bs + blockSize, be + blockSize {
		aesBlk.Decrypt(plainText[bs: be], cryptedText[bs:be])
	}
	return _PKCS5UnPadding(plainText)
}
