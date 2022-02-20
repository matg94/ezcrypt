package ezcrypt

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"os"
	"strings"
)

func VerifySignature() {}

func GenerateSignature() {}

func GenerateSignatureToFile() {}

func VerifyFileSignature() {}

func EncryptFile(publicKey *rsa.PublicKey, filepath string) error {
	plainTextFile, err := os.ReadFile(filepath)
	if err != nil {
		return err
	}

	cipherTextFile, err := Encrypt(publicKey, string(plainTextFile))
	if err != nil {
		return err
	}
	err = ioutil.WriteFile(filepath+".ezcrypt", []byte(cipherTextFile), 0644)
	if err != nil {
		return err
	}
	return nil
}

func DecryptFile(privateKey *rsa.PrivateKey, filepath string) error {
	cipherTextFile, err := os.ReadFile(filepath)
	if err != nil {
		return err
	}

	plainTextFile, err := Decrypt(privateKey, string(cipherTextFile))
	if err != nil {
		return err
	}
	filePathSplit := strings.Split(filepath, ".")
	newFilePath := strings.Join(filePathSplit[:len(filePathSplit)-1], ".")
	err = ioutil.WriteFile(newFilePath, []byte(plainTextFile), 0644)
	if err != nil {
		return err
	}
	return nil
}

func Encrypt(publicKey *rsa.PublicKey, plaintext string) (string, error) {
	label := []byte("OAEP Encrypted")
	rng := rand.Reader
	ciphertext, err := rsa.EncryptOAEP(sha256.New(), rng, publicKey, []byte(plaintext), label)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

func Decrypt(privateKey *rsa.PrivateKey, cipher string) (string, error) {
	ciphertext, err := base64.StdEncoding.DecodeString(cipher)
	if err != nil {
		fmt.Println("Failed to base64 decode", err)
	}

	label := []byte("OAEP Encrypted")
	rng := rand.Reader

	plaintext, err := rsa.DecryptOAEP(sha256.New(), rng, privateKey, ciphertext, label)
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}
