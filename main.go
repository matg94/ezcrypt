package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"os"
)

type Action struct {
	Encrypt  bool
	Decrypt  bool
	Generate bool
	Sign     bool
	Verify   bool
}

type Flags struct {
	PublicKey  string
	PrivateKey string
	FilePath   string
	Target     string
}

func checkOneActionFlag(bools ...bool) bool {
	count := 0
	for _, b := range bools {
		if b {
			count++
		}
	}
	return count == 1
}

func hasStandardInput() bool {
	fi, err := os.Stdin.Stat()
	if err != nil {
		log.Fatal(err)
	}
	if fi.Mode()&os.ModeNamedPipe == 0 {
		return false
	} else {
		return true
	}
}

func readStandardIn() string {
	scanner := bufio.NewScanner(os.Stdin)
	var finalString string
	for scanner.Scan() {
		finalString += scanner.Text() + "\n"
	}
	if err := scanner.Err(); err != nil {
		log.Fatalf("error reading standard in input")
	}
	return finalString
}

func executeAction(actions *Action, flags *Flags) {
	if actions.Encrypt {
		EncryptAction(flags)
	} else if actions.Decrypt {
		DecryptAction(flags)
	} else if actions.Generate {
		GenerateAction(flags)
	} else if actions.Sign {
		SignAction(flags)
	} else if actions.Verify {
		VerifyAction(flags)
	} else {
		log.Fatal("could not find an action to execute")
	}
}

func main() {

	standardInput := ""
	if hasStandardInput() {
		standardInput = readStandardIn()
	}
	fmt.Print(standardInput)

	flags := &Flags{}
	actions := &Action{}

	flag.StringVar(&flags.PublicKey, "pubkey", "./publicKey.pem", "Path to public key the default is ~/.ezcrypt/publicKey.pem. This path is relative to ~/.ezcrypt")
	flag.StringVar(&flags.PrivateKey, "privkey", "./privateKey.pem", "Path to private key the default is ~/.ezcrypt/privateKey.pem. This path is relative to ~/.ezcrypt")
	flag.StringVar(&flags.FilePath, "f", "", "Path to file to encrypt/decrypt, if not specified, piped string input will be encrypted")
	flag.StringVar(&flags.Target, "t", "", "If specified, ezcrypt will create and overwrite a file at this path with its output")

	flag.BoolVar(&actions.Encrypt, "enc", false, "Encrypt action mutually exclusive with other actions")
	flag.BoolVar(&actions.Decrypt, "dec", false, "Decrypt action mutually exclusive with other actions")
	flag.BoolVar(&actions.Generate, "gen", false, "Generate action used to generate keys: will overwrite default keys at ~/.ezcrypt/publicKey.pem and ~/.ezcrypt/privateKey.pem")
	flag.BoolVar(&actions.Sign, "sign", false, "Signature action will create a signature for given input")
	flag.BoolVar(&actions.Verify, "verify", false, "Will verify a signature given as input")

	flag.Parse()

	if !checkOneActionFlag(actions.Decrypt, actions.Encrypt, actions.Generate, actions.Sign, actions.Verify) {
		log.Fatal("exactly one action flag required but received either zero or multiple")
	}

	executeAction(actions, flags)

}
