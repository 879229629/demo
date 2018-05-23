package main

// test
// test2

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/smtp"
	"os"
	"reflect"
	"runtime"

	"github.com/879229629/demo/app"
	"github.com/gogo/protobuf/proto"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	gmail "google.golang.org/api/gmail/v1"
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

// Retrieve a token, saves the token, then returns the generated client.
func getClient(config *oauth2.Config) *http.Client {
	tokFile := "token.json"
	tok, err := tokenFromFile(tokFile)
	if err != nil {
		tok = getTokenFromWeb(config)
		saveToken(tokFile, tok)
	}
	return config.Client(context.Background(), tok)
}

// Request a token from the web, then returns the retrieved token.
func getTokenFromWeb(config *oauth2.Config) *oauth2.Token {
	authURL := config.AuthCodeURL("state-token", oauth2.AccessTypeOffline)
	fmt.Printf("Go to the following link in your browser then type the "+
		"authorization code: \n%v\n", authURL)

	var authCode string
	if _, err := fmt.Scan(&authCode); err != nil {
		log.Fatalf("Unable to read authorization code: %v", err)
	}

	tok, err := config.Exchange(oauth2.NoContext, authCode)
	if err != nil {
		log.Fatalf("Unable to retrieve token from web: %v", err)
	}
	return tok
}

// Retrieves a token from a local file.
func tokenFromFile(file string) (*oauth2.Token, error) {
	f, err := os.Open(file)
	defer f.Close()
	if err != nil {
		return nil, err
	}
	tok := &oauth2.Token{}
	err = json.NewDecoder(f).Decode(tok)
	return tok, err
}

// Saves a token to a file path.
func saveToken(path string, token *oauth2.Token) {
	fmt.Printf("Saving credential file to: %s\n", path)
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0600)
	defer f.Close()
	if err != nil {
		log.Fatalf("Unable to cache oauth token: %v", err)
	}
	json.NewEncoder(f).Encode(token)
}

func gmailtest() {
	b, err := ioutil.ReadFile("client_secret.json")
	if err != nil {
		log.Fatalf("Unable to read client secret file: %v", err)
	}

	// If modifying these scopes, delete your previously saved client_secret.json.
	config, err := google.ConfigFromJSON(b, gmail.GmailReadonlyScope)
	if err != nil {
		log.Fatalf("Unable to parse client secret file to config: %v", err)
	}

	srv, err := gmail.New(getClient(config))
	if err != nil {
		log.Fatalf("Unable to retrieve Gmail client: %v", err)
	}

	user := "me"
	r, err := srv.Users.Labels.List(user).Do()
	if err != nil {
		log.Fatalf("Unable to retrieve labels: %v", err)
	}
	if len(r.Labels) == 0 {
		fmt.Println("No labels found.")
		return
	}
	fmt.Println("Labels:")
	for _, l := range r.Labels {
		fmt.Printf("- %s\n", l.Name)
	}
}

var i int32 = 0

var queue = make(chan string, 2)

func read() {
	for elem := range queue {
		fmt.Println(elem)
	}
	fmt.Println("done")
}

func main() {
	s := app.Test()
	fmt.Println(s)
}

func testerror() (err error) {
	defer func() {
		fmt.Printf("BB: %v\n", err)

	}()
	fmt.Printf("AA: %v\n", err)
	return
}

func getResult(a proto.Message) {
	fmt.Printf("----- \n")
	val := reflect.Indirect(reflect.ValueOf(a))
	fmt.Println(val.Type().Field(0))
	fmt.Printf("----- \n")

	x := reflect.ValueOf(a).Elem().FieldByName("Result")
	code := x.Elem().FieldByName("ErrorCode")
	msg := x.Elem().FieldByName("ErrorMsg")

	fmt.Printf("** %+v \n %v \n %v\n", x, code, msg)

	a1, ok := code.Interface().(*int32)
	fmt.Printf("## ** %v %v \n", *a1, ok)
	a2, ok := msg.Interface().(*string)
	fmt.Printf("## ** %v %v \n", *a2, ok)

	// val.Type().Field(0).Name
	// val = val.FieldByName("result")
	// fmt.Printf("val: %+v \n", val.Name)

	pc := make([]uintptr, 10) // at least 1 entry needed
	runtime.Callers(2, pc)
	f := runtime.FuncForPC(pc[0])
	file, line := f.FileLine(pc[0])
	fmt.Printf("%s:%d %s\n", file, line, f.Name())

}

func testemail() {
	from := "gang.zeng@shopee.com"
	pass := "roiokmvgenobtpgh"
	to := "gang.zeng@shopee.com"

	body := "test 123 曾刚 from sz 12 2355555"
	msg := "From: " + from + "\n" +
		"To: " + to + "\n" +
		"Subject: Hello there\n\n" +
		body

	err := smtp.SendMail("smtp.gmail.com:587",
		smtp.PlainAuth("", from, pass, "smtp.gmail.com"),
		from, []string{to}, []byte(msg))

	if err != nil {
		log.Printf("smtp error: %s", err)
		return
	}
	return
}
