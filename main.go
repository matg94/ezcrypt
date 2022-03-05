package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
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
	PublicKey         string
	PrivateKey        string
	FilePath          string
	Target            string
	SignatureFilePath string
}

var out io.Writer = os.Stdout

func output(values ...string) {
	for _, val := range values {
		fmt.Fprint(out, val)
	}
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

func executeAction(actions *Action, flags *Flags, standardIn string) {
	if actions.Encrypt {
		EncryptAction(flags, standardIn)
	} else if actions.Decrypt {
		DecryptAction(flags, standardIn)
	} else if actions.Generate {
		GenerateAction(flags)
	} else if actions.Sign {
		SignAction(flags, standardIn)
	} else if actions.Verify {
		VerifyAction(flags, standardIn)
	} else {
		log.Fatal("could not find an action to execute")
	}
}

func main() {

	standardInput := ""
	if hasStandardInput() {
		standardInput = readStandardIn()
	}

	flags := &Flags{}
	actions := &Action{}

	flag.StringVar(&flags.PublicKey, "pubkey", "./publicKey.pem", "Path to public key the default is ./publicKey.pem.")
	flag.StringVar(&flags.PrivateKey, "privkey", "./privateKey.pem", "Path to private key the default is ./privateKey.pem.")
	flag.StringVar(&flags.FilePath, "f", "", "Path to file to encrypt/decrypt, if not specified, piped string input will be encrypted")
	flag.StringVar(&flags.Target, "t", "", "If specified, ezcrypt will create and overwrite a file at this path with its output")
	flag.StringVar(&flags.SignatureFilePath, "s", "", "The filepath pointing to the signature file when verifying a signature")

	flag.BoolVar(&actions.Encrypt, "enc", false, "Encrypt action mutually exclusive with other actions")
	flag.BoolVar(&actions.Decrypt, "dec", false, "Decrypt action mutually exclusive with other actions")
	flag.BoolVar(&actions.Generate, "gen", false, "Generate action used to generate keys: will overwrite keys at ./publicKey.pem and ./privateKey.pem")
	flag.BoolVar(&actions.Sign, "sign", false, "Signature action will create a signature for given input")
	flag.BoolVar(&actions.Verify, "verify", false, "Will verify a signature given as input")

	flag.Parse()

	if !checkOneActionFlag(actions.Decrypt, actions.Encrypt, actions.Generate, actions.Sign, actions.Verify) {
		log.Fatal("exactly one action flag required but received either zero or multiple")
	}

	executeAction(actions, flags, standardInput)

}
