package main

// test

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	_ "net/http/pprof"
	"time"

	"github.com/samuel/go-zookeeper/zk"
)

func PKCS5Padding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}

func PKCS5UnPadding(origData []byte) []byte {
	length := len(origData)
	unpadding := int(origData[length-1])
	return origData[:(length - unpadding)]
}

func encrypt(key []byte, message string) (encmess string, err error) {
	plainText := PKCS5Padding([]byte(message), aes.BlockSize)

	block, err := aes.NewCipher(key)
	if err != nil {
		return
	}

	iv := make([]byte, aes.BlockSize)
	if _, err = io.ReadFull(rand.Reader, iv); err != nil {
		return
	}

	blockMode := cipher.NewCBCEncrypter(block, iv)
	crypted := make([]byte, len(plainText))
	blockMode.CryptBlocks(crypted, plainText)

	crypted = append(iv, crypted...)
	encmess = base64.StdEncoding.EncodeToString(crypted)
	return
}

func decrypt(key []byte, securemess string) (decodedmess string, err error) {
	cipherText, err := base64.StdEncoding.DecodeString(securemess)
	if err != nil {
		return
	}

	if len(cipherText) < aes.BlockSize {
		err = errors.New("Ciphertext block size is too short!")
		return
	}

	iv := cipherText[:aes.BlockSize]
	cipherText = cipherText[aes.BlockSize:]

	block, err := aes.NewCipher(key)
	if err != nil {
		return
	}
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(cipherText, cipherText)

	decodedmess = string(PKCS5UnPadding(cipherText))
	return
}

const token = "bSI1MtWOn3ccBJjf5Y2ZBE8ZZEQsQPqG"

func main() {

	for i := 0; i < 10000; i++ {
		time.Sleep(1 * time.Second)

		c, _, err := zk.Connect([]string{"127.0.0.1"}, time.Second) //*10)
		if err != nil {
			panic(err)
		}

		p, e := c.Create("/services/dp-huborder-test-th/127.0.0.1:8183", nil, zk.FlagEphemeral, zk.WorldACL(zk.PermAll))
		if e != nil {
			fmt.Printf("path: %s, e: %v\n", p, e)
			break
		}

		time.Sleep(10 * time.Second)
		c.Close()
	}

	fmt.Println(" ###################### ")
}
