package ezcrypt

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
)

func DecodePrivateKey(encodedPrivateKey []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(encodedPrivateKey)
	if block == nil {
		return nil, fmt.Errorf("could not decode private key: not of pem type")
	}
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return key, nil
}

func DecodePublicKey(encodedPublicKey []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode(encodedPublicKey)
	if block == nil {
		return nil, fmt.Errorf("could not decode public key: not of pem type")
	}
	key, err := x509.ParsePKCS1PublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return key, nil
}

func EncodePrivateKey(decodedPrivateKey *rsa.PrivateKey) ([]byte, error) {
	privateKeyPEM := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(decodedPrivateKey),
	}
	keyBuffer := bytes.NewBufferString("")
	if err := pem.Encode(keyBuffer, privateKeyPEM); err != nil {
		return nil, err
	}

	return keyBuffer.Bytes(), nil
}

func EncodePublicKey(decodedPublicKey *rsa.PublicKey) ([]byte, error) {
	publicKeyPem := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: x509.MarshalPKCS1PublicKey(decodedPublicKey),
	}
	keyBuffer := bytes.NewBufferString("")
	if err := pem.Encode(keyBuffer, publicKeyPem); err != nil {
		return nil, err
	}

	return keyBuffer.Bytes(), nil
}

func GeneratePrivateKey() (*rsa.PrivateKey, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, err
	}
	return privateKey, nil
}

func GetPublicKey(decodedPrivateKey *rsa.PrivateKey) *rsa.PublicKey {
	return &decodedPrivateKey.PublicKey
}

func ReadPrivateKeyFromFile(filepath string) ([]byte, error) {
	encodedPrivateKey, err := ioutil.ReadFile(filepath)
	if err != nil {
		return nil, err
	}
	return encodedPrivateKey, nil
}

func ReadPublicKeyFromFile(filepath string) ([]byte, error) {
	encodedPublicKey, err := ioutil.ReadFile(filepath)
	if err != nil {
		return nil, err
	}
	return encodedPublicKey, nil
}

func WritePrivateKeyToFile(filepath string, encodedPrivateKey []byte) error {
	err := ioutil.WriteFile(filepath, encodedPrivateKey, 0644)
	if err != nil {
		return err
	}
	return nil
}

func WritePublicKeyToFile(filepath string, encodedPublicKey []byte) error {
	err := ioutil.WriteFile(filepath, encodedPublicKey, 0644)
	if err != nil {
		return err
	}
	return nil
}
