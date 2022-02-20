package ezcrypt

import (
	"os"
	"testing"
)

func cleanUpFile(t *testing.T, filepath string) {
	err := os.Remove(filepath)
	if err != nil {
		t.Logf("failed to clean up file after test: %v", err)
		t.Fail()
	}
}

func TestDecodePrivateKey(t *testing.T) {
	privateKey, _ := GeneratePrivateKey()
	encodedPrivateKey, _ := EncodePrivateKey(privateKey)
	decodedPrivateKey, err := DecodePrivateKey(encodedPrivateKey)
	if err != nil {
		t.Logf("expected err to be <nil> but got %v", err)
		t.Fail()
	}
	if decodedPrivateKey.Size() != privateKey.Size() {
		t.Logf("expected private key to have match size after decoding but got %d and %d",
			decodedPrivateKey.Size(), privateKey.Size())
		t.Fail()
	}
	if decodedPrivateKey.E != privateKey.E {
		t.Logf("expected E value to match after decoding but got %d and %d",
			decodedPrivateKey.E, privateKey.E)
		t.Fail()
	}
}

func TestDecodePublicKey(t *testing.T) {
	privateKey, _ := GeneratePrivateKey()
	publicKey := GetPublicKey(privateKey)

	encodedPublicKey, _ := EncodePublicKey(publicKey)
	decodedPublicKey, err := DecodePublicKey(encodedPublicKey)
	if err != nil {
		t.Logf("expected err to be <nil> but got %v", err)
		t.Fail()
	}
	if decodedPublicKey.Size() != publicKey.Size() {
		t.Logf("expected public key to have match size after decoding but got %d and %d",
			decodedPublicKey.Size(), publicKey.Size())
		t.Fail()
	}
	if decodedPublicKey.E != publicKey.E {
		t.Logf("expected E value to match after decoding but got %d and %d",
			decodedPublicKey.E, publicKey.E)
		t.Fail()
	}
}

func TestEncodePrivateKey(t *testing.T) {
	privateKey, _ := GeneratePrivateKey()
	encodedPrivateKey, err := EncodePrivateKey(privateKey)
	decodedPrivateKey, _ := DecodePrivateKey(encodedPrivateKey)
	if err != nil {
		t.Logf("expected err to be <nil> but got %v", err)
		t.Fail()
	}
	if decodedPrivateKey.Size() != privateKey.Size() {
		t.Logf("expected private key to have match size after decoding but got %d and %d",
			decodedPrivateKey.Size(), privateKey.Size())
		t.Fail()
	}
	if decodedPrivateKey.E != privateKey.E {
		t.Logf("expected E value to match after decoding but got %d and %d",
			decodedPrivateKey.E, privateKey.E)
		t.Fail()
	}
}

func TestEncodePublicKey(t *testing.T) {
	privateKey, _ := GeneratePrivateKey()
	publicKey := GetPublicKey(privateKey)
	encodedPublicKey, err := EncodePublicKey(publicKey)
	decodedPublicKey, _ := DecodePublicKey(encodedPublicKey)

	if err != nil {
		t.Logf("expected err to be <nil> but got %v", err)
		t.Fail()
	}
	if decodedPublicKey.Size() != publicKey.Size() {
		t.Logf("expected public key to have match size after decoding but got %d and %d",
			decodedPublicKey.Size(), publicKey.Size())
		t.Fail()
	}
	if decodedPublicKey.E != publicKey.E {
		t.Logf("expected E value to match after decoding but got %d and %d",
			decodedPublicKey.E, publicKey.E)
		t.Fail()
	}
}

func TestGeneratePrivateKey(t *testing.T) {
	privateKey, err := GeneratePrivateKey()
	if err != nil {
		t.Logf("expected err to be <nil> but got %v", err)
		t.Fail()
	}
	if privateKey.Size() != 512 {
		t.Logf("expected private key to have size 512 but got %d", privateKey.PublicKey.Size())
		t.Fail()
	}
}

func TestGeneratePublicKey(t *testing.T) {
	privateKey, _ := GeneratePrivateKey()
	publicKey := GetPublicKey(privateKey)
	if publicKey.Size() != 512 {
		t.Logf("expected public key to have size 512 but got %d", privateKey.PublicKey.Size())
		t.Fail()
	}
}

func TestReadPrivateKey(t *testing.T) {
	privateKey, _ := GeneratePrivateKey()
	encodedPrivateKey, _ := EncodePrivateKey(privateKey)
	WritePrivateKeyToFile("./testPrivate.pem", encodedPrivateKey)

	privateKeyRead, err := ReadPrivateKeyFromFile("./testPrivate.pem")
	if err != nil {
		t.Logf("expected err to be <nil> but got %v", err)
		t.Fail()
	}
	decodedPrivateKeyRead, _ := DecodePrivateKey(privateKeyRead)
	if decodedPrivateKeyRead.Size() != privateKey.Size() {
		t.Logf("expected private key to have match size after decoding but got %d and %d",
			decodedPrivateKeyRead.Size(), privateKey.Size())
		t.Fail()
	}
	if decodedPrivateKeyRead.E != privateKey.E {
		t.Logf("expected E value to match after decoding but got %d and %d",
			decodedPrivateKeyRead.E, privateKey.E)
		t.Fail()
	}
	cleanUpFile(t, "./testPrivate.pem")
}

func TestReadPublicKey(t *testing.T) {
	privateKey, _ := GeneratePrivateKey()
	publicKey := GetPublicKey(privateKey)
	encodedPublicKey, _ := EncodePublicKey(publicKey)
	WritePublicKeyToFile("./testPublic.pem", encodedPublicKey)

	publicKeyRead, err := ReadPublicKeyFromFile("./testPublic.pem")
	if err != nil {
		t.Logf("expected err to be <nil> but got %v", err)
		t.Fail()
	}
	decodedPublicKeyRead, _ := DecodePublicKey(publicKeyRead)
	if decodedPublicKeyRead.Size() != publicKey.Size() {
		t.Logf("expected public key to have match size after decoding but got %d and %d",
			decodedPublicKeyRead.Size(), publicKey.Size())
		t.Fail()
	}
	if decodedPublicKeyRead.E != publicKey.E {
		t.Logf("expected E value to match after decoding but got %d and %d",
			decodedPublicKeyRead.E, publicKey.E)
		t.Fail()
	}
	cleanUpFile(t, "./testPublic.pem")
}

func TestWritePrivateKey(t *testing.T) {
	privateKey, _ := GeneratePrivateKey()
	encodedPrivateKey, _ := EncodePrivateKey(privateKey)
	err := WritePrivateKeyToFile("./testPrivate.pem", encodedPrivateKey)
	if err != nil {
		t.Logf("expected err to be <nil> but got %v", err)
		t.Fail()
	}
	_, err = os.Stat("./testPrivate.pem")
	if err != nil {
		t.Logf("expected no errors accessing file but got %v", err)
	}
	privateKeyRead, _ := ReadPrivateKeyFromFile("./testPrivate.pem")
	decodedPrivateKeyRead, _ := DecodePrivateKey(privateKeyRead)
	if decodedPrivateKeyRead.Size() != privateKey.Size() {
		t.Logf("expected private key to have match size after decoding but got %d and %d",
			decodedPrivateKeyRead.Size(), privateKey.Size())
		t.Fail()
	}
	if decodedPrivateKeyRead.E != privateKey.E {
		t.Logf("expected E value to match after decoding but got %d and %d",
			decodedPrivateKeyRead.E, privateKey.E)
		t.Fail()
	}
	cleanUpFile(t, "./testPrivate.pem")
}

func TestWritePublicKey(t *testing.T) {
	privateKey, _ := GeneratePrivateKey()
	publicKey := GetPublicKey(privateKey)
	encodedPublicKey, _ := EncodePublicKey(publicKey)
	err := WritePublicKeyToFile("./testPublic.pem", encodedPublicKey)
	if err != nil {
		t.Logf("expected err to be <nil> but got %v", err)
		t.Fail()
	}
	_, err = os.Stat("./testPublic.pem")
	if err != nil {
		t.Logf("expected no errors accessing file but got %v", err)
	}
	publicKeyRead, _ := ReadPublicKeyFromFile("./testPublic.pem")
	decodedPublicKeyRead, _ := DecodePublicKey(publicKeyRead)
	if decodedPublicKeyRead.Size() != publicKey.Size() {
		t.Logf("expected public key to have match size after decoding but got %d and %d",
			decodedPublicKeyRead.Size(), publicKey.Size())
		t.Fail()
	}
	if decodedPublicKeyRead.E != publicKey.E {
		t.Logf("expected E value to match after decoding but got %d and %d",
			decodedPublicKeyRead.E, publicKey.E)
		t.Fail()
	}
	cleanUpFile(t, "./testPublic.pem")
}
