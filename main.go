package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"

	"git.garena.com/lixh/goorm"
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

// func main() {
// 	// msg := "abc"
// 	// password, err := encrypt([]byte(token), msg)
// 	// if err != nil {
// 	// 	panic(err.Error())
// 	// }
// 	// fmt.Printf("加密:\n %s \n%s \n%d \n%s \n", token, msg, len(msg), password)

// 	password := "ErVzxC8s9S+2mVbA5dGb6oQYoatDUQoqbnb8+Gj0a3aqM6EHXXdhnVM1Ce9IuWeeVjG3DRfTfM2OgxVbFZi40G22AsWI87QttMqSGLYBDhim69FhcIpAmnKGItaBEmZjBLWtnuuYWtFXjf63/Yx1OA=="

// 	password = "jrgTROQxnfxVh02urM1oouLWliI+doYWHcCi8tCbXwpWpPS0taQ4fgzLIzRO9pZ+CbCXLRs5rFKK/ALd9s2UOEcpu0slaiu6MJmTMNVRcNaeUF3c00+6KE910Mihorgs"

// 	password = "kZIL8IJwPuchvQ+ycDnaMcbfWGlj5+AOjXjR/8KqcX5Nb24NUL8X3lWufcWfZycsBtBZVe3QpNBwRd1f+KLaUw2bSAxLQscXhwAKZ0zKZ3n6K64AesS5HLq+B4ssU3rT"

// 	msg2, err := decrypt([]byte(token), password)
// 	if err != nil {
// 		panic(err.Error())
// 	}
// 	fmt.Printf("解密: \n%s \n%s \n%d \n%s \n", token, msg2, len(msg2), password)

// 	//

// }

func log1(format string, arg ...interface{}) {
	fmt.Sprintf(format, arg...)
}

func init() {
	goorm.RegisterLogFunction(log1, true)

	goorm.RegisterDataBase("entry_db", "mysql", 10, 10, true, "dev:dev@tcp(127.0.0.1:3306)/entry_db?timeout=10s")

	// user := &User{}

	// mi := goorm.RegisterModel(user)

	// mi.SetPrimayColumn("id", true)

	// mi.SetSplitInfo("userid", SplitKeyMethodMod, 10, "")
}

func main() {

	const s = "48656c6c6f20476f7068657221"
	decoded, err := hex.DecodeString(s)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("%s\n", decoded)

	s1 := hex.EncodeToString(decoded)
	fmt.Printf("%s \n", s1)

}
