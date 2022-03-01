package main

import (
	"fmt"
	"io/ioutil"
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

func EncryptAction(flags *Flags, standardIn string) {
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
	} else if standardIn != "" {
		cipher, err := ezcrypt.Encrypt(decodedPublicKey, standardIn)
		HandleError(err)
		if flags.Target != "" {
			err = ioutil.WriteFile(flags.Target, []byte(cipher), 0644)
			HandleError(err)
		} else {
			output(cipher)
		}
	}
}

func DecryptAction(flags *Flags, standardIn string) {
	encodedPrivateKey, err := ezcrypt.ReadPrivateKeyFromFile(flags.PrivateKey)
	HandleError(err)
	decodedPrivateKey, err := ezcrypt.DecodePrivateKey(encodedPrivateKey)
	HandleError(err)
	if flags.FilePath != "" {
		if flags.Target != "" {
			ezcrypt.DecryptFile(decodedPrivateKey, flags.FilePath, flags.Target)
		} else {
			cipherTextFile, err := os.ReadFile(flags.FilePath)
			HandleError(err)
			plaintext, err := ezcrypt.Decrypt(decodedPrivateKey, string(cipherTextFile))
			HandleError(err)
			output(plaintext)
		}
	} else if standardIn != "" {
		plaintext, err := ezcrypt.Decrypt(decodedPrivateKey, standardIn)
		HandleError(err)
		if flags.Target != "" {
			err = ioutil.WriteFile(flags.Target, []byte(plaintext), 0644)
			HandleError(err)
		} else {
			output(plaintext)
		}
	}
}

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

func SignAction(flags *Flags, standardIn string) {
	encodedPrivateKey, err := ezcrypt.ReadPrivateKeyFromFile(flags.PrivateKey)
	HandleError(err)
	decodedPrivateKey, err := ezcrypt.DecodePrivateKey(encodedPrivateKey)
	HandleError(err)
	if flags.FilePath != "" {
		signature, err := ezcrypt.GenerateSignatureForFile(decodedPrivateKey, flags.FilePath)
		HandleError(err)
		if flags.Target != "" {
			err = ioutil.WriteFile(flags.Target, []byte(signature), 0644)
			HandleError(err)
		} else {
			output(signature)
		}
	} else if standardIn != "" {
		signature, err := ezcrypt.GenerateSignature(decodedPrivateKey, standardIn)
		HandleError(err)
		if flags.Target != "" {
			err = ioutil.WriteFile(flags.Target, []byte(signature), 0644)
			HandleError(err)
		} else {
			output(signature)
		}
	}
}

func VerifyAction(flags *Flags, standardIn string) {
	if flags.SignatureFilePath == "" {
		HandleError(fmt.Errorf("-s file path is not set: this needs to point to a signature file"))
		return
	}
	signature, err := os.ReadFile(flags.SignatureFilePath)
	HandleError(err)
	encodedPublicKey, err := ezcrypt.ReadPublicKeyFromFile(flags.PublicKey)
	HandleError(err)
	decodedPublicKey, err := ezcrypt.DecodePublicKey(encodedPublicKey)
	HandleError(err)
	verified := false
	if flags.FilePath != "" {
		signedBody, err := os.ReadFile(flags.FilePath)
		HandleError(err)
		verified, err = ezcrypt.VerifySignature(decodedPublicKey, string(signedBody), string(signature))
		HandleError(err)
	} else {
		verified, err = ezcrypt.VerifySignature(decodedPublicKey, standardIn, string(signature))
		HandleError(err)
	}
	if verified {
		output("valid")
		return
	}
	output("invalid")
}
