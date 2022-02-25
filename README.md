# ezcrypt - A CLI for quick & simple RSA encryptions

Quickly and easily encrypt with an RSA encryption

## Installation

Run `go install github.com/matg94/ezcrypt`

## Usage

### Generating & Using Keys

Keys named `publicKey.pem` and `privateKey.pem` stored in `~/.ezcrypt` will be used by default.
You can use ezcrypt to generate keys there, are you can provide your own.

Alternatively, you can use your own keys by passing the key path with the appropriate flag, i.e
`-pubkey=<PATH/TO/PUBKEYFILE>` or `-privkey=<PATH/TO/PRIVKEYFILE>`
The path will be relative to the `/.ezcrypt` directory, so keys placed in there just need to pass the filename.

These need to be stored in the `.pem` format.

To generate a new keypair in the default directory, use the following command
`ezcrypt -gen`

To generate a new keypair in a specific directory, use the `-pubkey` and `-privkey` fields.
This will check for existing keys to avoid accidental overwrites.

`ezcrypt -gen -pubkey=<PATH/TO/NEWPUBKEY.pem> -privkey=<PATH/TO/NEWPRIVKEY.pem>`

### Encryption

#### String Encryption

String encryption works by piping your string into ezcrypt.

To encrypt a string, you can use the following command:
`echo <string> | ezcrypt enc [-pubkey=/path/to/pubkey.pem]`

This will output the encrypted value.

#### File Encryption

To encrypt a file, you can use the `-f` path.
For example,
`ezcrypt enc [-pubkey=/path/to/pubkey.pem] -f path/to/file [-t path/to/destinationfile]`

A `-t` flag can be specified to set the target file manually, otherwise, it will override the original file

### Decryption

### String Decryption

String decryption works by piping your string into ezcrypt.

To decrypt a string, you can use the following command:
`echo <string> | ezcrypt dec [-privkey=/path/to/privkey.pem]`

This will output the decrypted value.

### File Decryption

To decrypt a file, you can use the `-f` flag to specify the filepath.
The `-t` path is option, and will create the new decrypted file at that path. 
For example,
`ezcrypt dec [-pubkey=/path/to/pubkey.pem] -f path/to/file [-t path/to/destinationfile]`

A `-t` flag can be specified to set the target file manually, otherwise, it will override the original file

### Signatures & Verification