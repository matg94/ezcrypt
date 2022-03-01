package main

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"os"
	"testing"
)

func setupTestEnv() string {
	flags := &Flags{
		PublicKey:         "./publicKey.pem",
		PrivateKey:        "./privateKey.pem",
		FilePath:          "",
		Target:            "",
		SignatureFilePath: "",
	}

	GenerateAction(flags)

	buf := &bytes.Buffer{}
	out = buf
	EncryptAction(flags, "test")

	flags = &Flags{
		PublicKey:         "./publicKey.pem",
		PrivateKey:        "./privateKey.pem",
		FilePath:          "",
		Target:            "./signature",
		SignatureFilePath: "",
	}

	SignAction(flags, "test")

	return buf.String()
}

func cleanupTestEnv(t *testing.T) {
	cleanUpFile(t, "./publicKey.pem")
	cleanUpFile(t, "./privateKey.pem")
	cleanUpFile(t, "./signature")
}

func HandleTestError(t *testing.T, err error) {
	if err != nil {
		t.Logf("failed due to error: %v", err)
		t.Fail()
	}
}

func fileExists(filepath string) bool {
	_, err := os.Stat(filepath)
	return err == nil
}

func cleanUpFile(t *testing.T, filepath string) {
	err := os.Remove(filepath)
	if err != nil {
		t.Logf("failed to clean up file after test: %v", err)
		t.Fail()
	}
}

func TestCheckExistenceOfFile(t *testing.T) {
	ioutil.WriteFile("./testFile", []byte("test"), 0644)
	files, err := CheckForExistenceOfFile("./testFile", "./notexist")

	HandleTestError(t, err)
	testFileFound := false
	for _, v := range files {
		if v == "./testFile" {
			testFileFound = true
		}
	}
	if !testFileFound {
		t.Log("expected ./testFile to be found but didn't")
		t.Fail()
	}
	cleanUpFile(t, "./testFile")

}

func TestEncryptActionStringToString(t *testing.T) {
	setupTestEnv()
	defer cleanupTestEnv(t)

	buf := &bytes.Buffer{}
	out = buf

	flags := &Flags{
		PublicKey:         "./publicKey.pem",
		PrivateKey:        "",
		FilePath:          "",
		Target:            "",
		SignatureFilePath: "",
	}

	EncryptAction(flags, "test")

	if buf.String() == "" {
		t.Log("expected output but did not get any")
		t.Fail()
	}
}

func TestEncryptActionFileToString(t *testing.T) {
	setupTestEnv()
	defer cleanupTestEnv(t)

	buf := &bytes.Buffer{}
	out = buf

	ioutil.WriteFile("./testFile", []byte("test"), 0644)

	flags := &Flags{
		PublicKey:         "./publicKey.pem",
		PrivateKey:        "",
		FilePath:          "./testFile",
		Target:            "",
		SignatureFilePath: "",
	}

	EncryptAction(flags, "test")

	if buf.String() == "" {
		t.Log("expected output but did not get any")
		t.Fail()
	}

	cleanUpFile(t, "./testFile")

}
func TestEncryptActionStringToFile(t *testing.T) {
	setupTestEnv()
	defer cleanupTestEnv(t)

	buf := &bytes.Buffer{}
	out = buf

	flags := &Flags{
		PublicKey:         "./publicKey.pem",
		PrivateKey:        "",
		FilePath:          "",
		Target:            "./testFile.enc",
		SignatureFilePath: "",
	}

	EncryptAction(flags, "test")

	if buf.String() != "" {
		t.Logf("expected no output but got: %s", buf.String())
		t.Fail()
	}

	if !fileExists("./testFile.enc") {
		t.Logf("expected file to be generated but could not find it")
		t.Fail()
	}

	cleanUpFile(t, "./testFile.enc")
}

func TestEncryptionActionFileToFile(t *testing.T) {
	setupTestEnv()
	defer cleanupTestEnv(t)

	buf := &bytes.Buffer{}
	out = buf

	ioutil.WriteFile("./testFile", []byte("test"), 0644)

	flags := &Flags{
		PublicKey:         "./publicKey.pem",
		PrivateKey:        "",
		FilePath:          "./testFile",
		Target:            "./testFile.enc",
		SignatureFilePath: "",
	}

	EncryptAction(flags, "")

	if buf.String() != "" {
		t.Logf("expected no output but got: %s", buf.String())
		t.Fail()
	}

	if !fileExists("./testFile.enc") {
		t.Logf("expected file to be generated but could not find it")
		t.Fail()
	}

	cleanUpFile(t, "./testFile")
	cleanUpFile(t, "./testFile.enc")

}

func TestDecryptActionStringToString(t *testing.T) {
	encryptedTest := setupTestEnv()
	defer cleanupTestEnv(t)

	buf := &bytes.Buffer{}
	out = buf

	flags := &Flags{
		PublicKey:         "",
		PrivateKey:        "./privateKey.pem",
		FilePath:          "",
		Target:            "",
		SignatureFilePath: "",
	}

	DecryptAction(flags, encryptedTest)

	if buf.String() == "" {
		t.Log("expected output but did not get any")
		t.Fail()
	}
}

func TestDecryptActionFileToString(t *testing.T) {
	encryptedTest := setupTestEnv()
	defer cleanupTestEnv(t)

	buf := &bytes.Buffer{}
	out = buf

	ioutil.WriteFile("./testFile", []byte(encryptedTest), 0644)

	flags := &Flags{
		PublicKey:         "",
		PrivateKey:        "./privateKey.pem",
		FilePath:          "./testFile",
		Target:            "",
		SignatureFilePath: "",
	}

	DecryptAction(flags, "")

	fmt.Println(buf.String())

	if buf.String() == "" {
		t.Log("expected output but did not get any")
		t.Fail()
	}

	cleanUpFile(t, "./testFile")

}

func TestDecryptActionStringToFile(t *testing.T) {
	encryptedTest := setupTestEnv()
	defer cleanupTestEnv(t)

	buf := &bytes.Buffer{}
	out = buf

	flags := &Flags{
		PublicKey:         "",
		PrivateKey:        "./privateKey.pem",
		FilePath:          "",
		Target:            "./testFile",
		SignatureFilePath: "",
	}

	DecryptAction(flags, encryptedTest)

	if buf.String() != "" {
		t.Logf("expected no output but got: %s", buf.String())
		t.Fail()
	}

	if !fileExists("./testFile") {
		t.Logf("expected file to be generated but could not find it")
		t.Fail()
	}

	cleanUpFile(t, "./testFile")

}

func TestDecryptActionFileToFile(t *testing.T) {
	encryptedTest := setupTestEnv()
	defer cleanupTestEnv(t)

	buf := &bytes.Buffer{}
	out = buf

	ioutil.WriteFile("./testFile.enc", []byte(encryptedTest), 0644)

	flags := &Flags{
		PublicKey:         "",
		PrivateKey:        "./privateKey.pem",
		FilePath:          "./testFile.enc",
		Target:            "./testFile",
		SignatureFilePath: "",
	}

	DecryptAction(flags, "")

	if buf.String() != "" {
		t.Logf("expected no output but got: %s", buf.String())
		t.Fail()
	}

	if !fileExists("./testFile") {
		t.Logf("expected file to be generated but could not find it")
		t.Fail()
	}

	cleanUpFile(t, "./testFile")
	cleanUpFile(t, "./testFile.enc")
}

func TestGenerateAction(t *testing.T) {

	flags := &Flags{
		PublicKey:         "./publicKey.pem",
		PrivateKey:        "./privateKey.pem",
		FilePath:          "",
		Target:            "",
		SignatureFilePath: "",
	}

	GenerateAction(flags)

	if !fileExists("./publicKey.pem") {
		t.Log("public key file was not generated")
		t.Fail()
	}
	if !fileExists("./privateKey.pem") {
		t.Log("private key file was not generated")
		t.Fail()
	}

	cleanUpFile(t, "./publicKey.pem")
	cleanUpFile(t, "./privateKey.pem")
}

func TestSignActionStringToString(t *testing.T) {
	setupTestEnv()
	defer cleanupTestEnv(t)

	buf := &bytes.Buffer{}
	out = buf

	flags := &Flags{
		PublicKey:         "",
		PrivateKey:        "./privateKey.pem",
		FilePath:          "",
		Target:            "",
		SignatureFilePath: "",
	}

	SignAction(flags, "test")

	if buf.String() == "" {
		t.Log("expected output but did not get any")
		t.Fail()
	}
}

func TestSignActionFileToString(t *testing.T) {
	setupTestEnv()
	defer cleanupTestEnv(t)

	buf := &bytes.Buffer{}
	out = buf

	ioutil.WriteFile("./testFile", []byte("test"), 0644)

	flags := &Flags{
		PublicKey:         "",
		PrivateKey:        "./privateKey.pem",
		FilePath:          "./testFile",
		Target:            "",
		SignatureFilePath: "",
	}

	SignAction(flags, "")

	if buf.String() == "" {
		t.Log("expected output but did not get any")
		t.Fail()
	}

	cleanUpFile(t, "./testFile")

}

func TestSignActionStringToFile(t *testing.T) {
	setupTestEnv()
	defer cleanupTestEnv(t)

	buf := &bytes.Buffer{}
	out = buf

	flags := &Flags{
		PublicKey:         "",
		PrivateKey:        "./privateKey.pem",
		FilePath:          "",
		Target:            "./testSignatureFile",
		SignatureFilePath: "",
	}

	SignAction(flags, "test")

	if buf.String() != "" {
		t.Logf("expected no output but got: %s", buf.String())
		t.Fail()
	}

	if !fileExists("./testSignatureFile") {
		t.Logf("expected file to be generated but could not find it")
		t.Fail()
	}

	cleanUpFile(t, "./testSignatureFile")

}

func TestSignActionFileToFile(t *testing.T) {
	encryptedTest := setupTestEnv()
	defer cleanupTestEnv(t)

	buf := &bytes.Buffer{}
	out = buf

	ioutil.WriteFile("./testFile.enc", []byte(encryptedTest), 0644)

	flags := &Flags{
		PublicKey:         "",
		PrivateKey:        "./privateKey.pem",
		FilePath:          "./testFile.enc",
		Target:            "./testSignatureFile",
		SignatureFilePath: "",
	}

	SignAction(flags, "")

	if buf.String() != "" {
		t.Logf("expected no output but got: %s", buf.String())
		t.Fail()
	}

	if !fileExists("./testSignatureFile") {
		t.Logf("expected file to be generated but could not find it")
		t.Fail()
	}

	cleanUpFile(t, "./testSignatureFile")
	cleanUpFile(t, "./testFile.enc")
}

func TestVerifyActionString(t *testing.T) {
	setupTestEnv()
	defer cleanupTestEnv(t)

	buf := &bytes.Buffer{}
	out = buf

	flags := &Flags{
		PublicKey:         "./publicKey.pem",
		PrivateKey:        "",
		FilePath:          "",
		Target:            "",
		SignatureFilePath: "./signature",
	}

	VerifyAction(flags, "test")

	if buf.String() != "valid" {
		t.Logf("expected 'valid' but got %s", buf.String())
		t.Fail()
	}
}

func TestVerifyActionFile(t *testing.T) {
	setupTestEnv()
	defer cleanupTestEnv(t)

	buf := &bytes.Buffer{}
	out = buf

	ioutil.WriteFile("./testFile", []byte("test"), 0644)

	flags := &Flags{
		PublicKey:         "./publicKey.pem",
		PrivateKey:        "",
		FilePath:          "./testFile",
		Target:            "",
		SignatureFilePath: "./signature",
	}

	VerifyAction(flags, "")

	if buf.String() != "valid" {
		t.Logf("expected 'valid' but got %s", buf.String())
		t.Fail()
	}

	cleanUpFile(t, "./testFile")
}
