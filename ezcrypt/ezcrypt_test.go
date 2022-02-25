package ezcrypt

import (
	"io/ioutil"
	"os"
	"testing"
)

func TestGenerateSignatureForFile(t *testing.T) {
	ioutil.WriteFile("./testFile.txt", []byte("test-content"), 0644)
	fileContent, _ := os.ReadFile("./testFile.txt")

	privateKey, _ := GeneratePrivateKey()

	signature, err := GenerateSignature(privateKey, string(fileContent))
	if err != nil {
		t.Logf("expected sign err to be <nil> but got %v", err)
		t.Fail()
	}

	if signature == "" {
		t.Logf("expected signature to have content")
		t.Fail()
	}

	valid, err := VerifySignature(&privateKey.PublicKey, string(fileContent), signature)

	if err != nil {
		t.Logf("expected verify signature err to be <nil> but got %v", err)
		t.Fail()
	}
	if !valid {
		t.Logf("expected signature to be valid")
		t.Fail()
	}
	cleanUpFile(t, "./testFile.txt")
}

func TestGenerateAndVerifySignature(t *testing.T) {
	privateKey, _ := GeneratePrivateKey()
	messageToSign := "test-signature-message"

	signature, err := GenerateSignature(privateKey, messageToSign)

	if err != nil {
		t.Logf("expected sign err to be <nil> but got %v", err)
		t.Fail()
	}

	if signature == "" {
		t.Logf("expected signature to have content")
		t.Fail()
	}

	valid, err := VerifySignature(&privateKey.PublicKey, messageToSign, signature)

	if err != nil {
		t.Logf("expected verify signature err to be <nil> but got %v", err)
		t.Fail()
	}
	if !valid {
		t.Logf("expected signature to be valid")
		t.Fail()
	}
}

func TestEncryptAndDecryptFile(t *testing.T) {
	privateKey, _ := GeneratePrivateKey()
	publicKey := GetPublicKey(privateKey)
	testEncryptionContent := "test-encryption-content"

	ioutil.WriteFile("./testFile.txt", []byte(testEncryptionContent), 0644)

	err := EncryptFile(publicKey, "./testFile.txt", "./testFile.txt.ezcrypt")
	if err != nil {
		t.Logf("expected encrypt file err to be <nil> but got %v", err)
		t.Fail()
	}

	cipherTextFile, err := os.ReadFile("./testFile.txt.ezcrypt")

	if err != nil {
		t.Logf("expected reading file err to be <nil> but got %v", err)
		t.Fail()
	}

	if string(cipherTextFile) == testEncryptionContent {
		t.Log("expected cipher and plaintext to be different")
		t.Fail()
	}

	cleanUpFile(t, "./testFile.txt")

	err = DecryptFile(privateKey, "./testFile.txt.ezcrypt", "./testFile.txt")
	if err != nil {
		t.Logf("expected decrypt file err to be <nil> but got %v", err)
		t.Fail()
	}
	decryptedPlainTextFile, err := os.ReadFile("./testFile.txt")
	if err != nil {
		t.Logf("expected reading decrypted file err to be <nil> but got %v", err)
		t.Fail()
	}

	if string(decryptedPlainTextFile) != testEncryptionContent {
		t.Log("expected decrypted content to match original")
		t.Fail()
	}

	cleanUpFile(t, "./testFile.txt.ezcrypt")
	cleanUpFile(t, "./testFile.txt")

}

func TestEncryptAndDecrypt(t *testing.T) {
	privateKey, _ := GeneratePrivateKey()
	publicKey := GetPublicKey(privateKey)

	testPlainText := "test-encryption-message"

	cipher, err := Encrypt(publicKey, testPlainText)
	if err != nil {
		t.Logf("expected encryption err to be <nil> but got %v", err)
		t.Fail()
	}
	if cipher == testPlainText {
		t.Logf("expected cipher to differ from plaintext but they matched")
		t.Fail()
	}
	plainTextDecrypted, err := Decrypt(privateKey, cipher)
	if err != nil {
		t.Logf("expected decryption err to be <nil> but got %v", err)
		t.Fail()
	}
	if plainTextDecrypted != testPlainText {
		t.Logf("expected decryption to return original plaintext but they did not match got: %s != %s", plainTextDecrypted, testPlainText)
		t.Fail()
	}
}
