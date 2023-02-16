package goaes

import (
	"crypto/cipher"
	"crypto/aes"
	"bytes"
	"fmt"
)

func _PKCS5Padding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext) % blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}

func _PKCS5UnPadding(origData []byte) ([]byte, error) {
	length := len(origData)
	unpadding := int(origData[length-1])
	if unpadding < 0 || unpadding >= length {
		return nil, fmt.Errorf("Invalid unpadding data: %d", unpadding)
	}
	return origData[:(length - unpadding)], nil
}

func adjustKey(key []byte) ([]byte, error) {
	if key == nil {
		return nil, fmt.Errorf("no key specified")
	}
	keyLen := len(key)
	switch keyLen {
	case 0:
		return nil, fmt.Errorf("no key specified")
	case 32, 24, 16:
		return key, nil
	default:
		if keyLen > 32 {
			return key[:32], nil
		}
		if keyLen > 24 {
			return key[:24], nil
		}
		if keyLen > 16 {
			return key[:16], nil
		}
		return nil, fmt.Errorf("key length must at least 16 bytes")
	}
}

func makeIv(key []byte, blockSize int, iv ...[]byte) (realIv []byte) {
	if len(iv) == 0 {
		realIv = key[:blockSize]
		return
	}

	if len(iv[0]) >= blockSize {
		realIv = iv[0][:blockSize]
		return
	}

	realIv = make([]byte, blockSize)
	if len(iv[0]) == 0 {
		return
	}

	copy(realIv, iv[0])
	return
}

func AesEncrypt(plainText []byte, key []byte, iv ...[]byte) ([]byte, error) {
	if len(plainText) == 0 {
		return nil, nil
	}

	realKey, err := adjustKey(key)
	if err != nil {
		return nil, err
	}
	aesBlk, _ := aes.NewCipher(realKey)
	blockSize := aesBlk.BlockSize()
	realIv := makeIv(key, blockSize, iv...)
	blockMode := cipher.NewCBCEncrypter(aesBlk, realIv)
	paddedPlainText := _PKCS5Padding(plainText, blockSize)
	crypted := make([]byte, len(paddedPlainText))
	blockMode.CryptBlocks(crypted, paddedPlainText)
	return crypted, nil
}

func AesDecrypt(cryptedText []byte, key []byte, iv ...[]byte) (b []byte, e error) {
	if len(cryptedText) == 0 {
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
	// fmt.Printf("blockSize: %d\n", blockSize)
	realIv := makeIv(key, blockSize, iv...)
	blockMode := cipher.NewCBCDecrypter(aesBlk, realIv)
	plainText := make([]byte, len(cryptedText))
	blockMode.CryptBlocks(plainText, cryptedText)
	return _PKCS5UnPadding(plainText)
}
