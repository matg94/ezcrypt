# ezcrypt - A CLI for quick & simple RSA encryptions

Quickly and easily encrypt with an RSA encryption

## Installation

Run `go install github.com/matg94/ezcrypt`

## Usage

### Generating Keys

Keys need to be in the `.pem` format.

Keys can be generated using the `-gen` action. 
Specifying the `-privkey=<path/to/file>` and `-pubkey=<path/to/file>` will generate the files at that location.
The default is the current directory.

`ezcrypt -gen -pubkey=<PATH/TO/NEWPUBKEY.pem> -privkey=<PATH/TO/NEWPRIVKEY.pem>`

### Encryption and Decryption

#### Encryption

You can pipe a string directly into ezcrypt to encrypt it. The output will be given as standard output.
for example,
`echo "hello" | ezcrypt -enc`

Alternatively, you can get input by passing the `-f` flag to specify a file to read from.

Flags:
    * Adding a `-f <path/to/file>` flag will read from that file rather than standard input
    * Adding a `-t <path/to/file>` flag will output to that path, rather than standard output
    * Adding a `-pubkey=<path/to/file>` flag will use the key at the given path, rather than looking for one in the current directory

e.g
`ezcrypt -enc -f ./fileToEncrypt -t ./encrytedFile -pubkey=/home/user/.ezcrypt/publicKey.pem`
will encrypt `fileToEncrypt` into a new file `encryptedFile` using the specified public key.


#### Decryption

Decryption follows the same format as encryption, but with the `-dec` action.

Flags:
    * Adding a `-f <path/to/file>` flag will read from that file rather than standard input
    * Adding a `-t <path/to/file>` flag will output to that path, rather than standard output
    * Adding a `-privkey=<path/to/file>` flag will use the key at the given path, rather than looking for one in the current directory

### Signatures & Verification

#### Signatures

To sign a string or file with your private key, you can use the `-sign` action.
You will need to provide the cipher to sign, either with standard in, or with the `-f` flag for a file.

Flags:
    * Adding a `-f <path/to/file>` flag will read from that file rather than standard input. This will read the body that needs to be signed
    * Adding a `-t <path/to/file>` flag will output the signature to that path, rather than standard output
    * Adding a `-privkey=<path/to/file>` flag will use the key at the given path, rather than looking for one in the current directory

#### Verifying a Signature

To verify a signature, use the `-verify` action.
You will need to provide the signature using the `-s <path/to/file>` flag,
and the body to verify, either using standard in, or the `-f <path/to/file>` flag.

The command will either output `valid` or `invalid` based on the validity of the signature and body combination.

A `pubkey=<path/to/pubkey>` flag needs to be provided, otherwise ezcrypt will look in the current directory for a `publicKey.pem` file.