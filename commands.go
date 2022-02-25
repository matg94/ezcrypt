package main

import (
	"fmt"
	"log"
	"os"

	"github.com/matg94/ezcrypt/ezcrypt"
)

func HandleError(err error) {
	if err != nil {
		log.Fatalf("There was a fatal error: %v", err)
	}
}

func CheckForExistenceOfFile(files ...string) ([]string, error) {
	var existingFiles []string
	for _, file := range files {
		_, err := os.Stat(file)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return []string{}, err
		}
		existingFiles = append(existingFiles, file)
	}
	return existingFiles, nil
}

func output(values ...string) {
	fmt.Print(values)
}

func EncryptAction(flags *Flags) {
	encodedPublicKey, err := ezcrypt.ReadPublicKeyFromFile(flags.PublicKey)
	HandleError(err)
	decodedPublicKey, err := ezcrypt.DecodePublicKey(encodedPublicKey)
	HandleError(err)
	if flags.FilePath != "" {
		if flags.Target != "" {
			ezcrypt.EncryptFile(decodedPublicKey, flags.FilePath, flags.Target)
		} else {
			plainTextFile, err := os.ReadFile(flags.FilePath)
			HandleError(err)
			cipher, err := ezcrypt.Encrypt(decodedPublicKey, string(plainTextFile))
			HandleError(err)
			output(cipher)
		}
	}
}

func DecryptAction(flags *Flags) {}

func GenerateAction(flags *Flags) {
	privateKey, err := ezcrypt.GeneratePrivateKey()
	HandleError(err)
	publicKey := ezcrypt.GetPublicKey(privateKey)
	encodedPrivateKey, err := ezcrypt.EncodePrivateKey(privateKey)
	HandleError(err)
	encodedPublicKey, err := ezcrypt.EncodePublicKey(publicKey)
	HandleError(err)
	existingFiles, err := CheckForExistenceOfFile(flags.PrivateKey, flags.PublicKey)
	HandleError(err)
	if len(existingFiles) > 0 {
		HandleError(fmt.Errorf("some files already exist, did not overwrite: %s", existingFiles))
	}
	err = ezcrypt.WritePrivateKeyToFile(flags.PrivateKey, encodedPrivateKey)
	HandleError(err)
	err = ezcrypt.WritePublicKeyToFile(flags.PublicKey, encodedPublicKey)
	HandleError(err)
}

func SignAction(flags *Flags) {}

func VerifyAction(flags *Flags) {}

/*

-t needs to work as a pipe for both string and file encryption

*/
