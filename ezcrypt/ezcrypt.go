package ezcrypt

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"os"
	"strings"
)

func VerifySignature(publicKey *rsa.PublicKey, message, signature string) (bool, error) {
	messageHash := sha256.New()
	_, err := messageHash.Write([]byte(message))
	if err != nil {
		return false, err
	}
	messageHashSum := messageHash.Sum(nil)

	if err != nil {
		return false, err
	}

	decodedSignature, err := base64.StdEncoding.DecodeString(signature)

	if err != nil {
		return false, err
	}

	err = rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, messageHashSum, decodedSignature)
	if err != nil {
		return false, err
	}
	return true, nil
}

func GenerateSignature(privateKey *rsa.PrivateKey, cipher string) (string, error) {
	messageHash := sha256.New()
	_, err := messageHash.Write([]byte(cipher))
	if err != nil {
		return "", err
	}
	messageHashSum := messageHash.Sum(nil)
	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, messageHashSum)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(signature), nil
}

func GenerateSignatureToFile() {}

func VerifySignatureFromFile() {}

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
