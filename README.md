# qryptex
A small encryption tool
## Rust implementation
Does not support creation and storing of a key pair.
Has no UI (yet?).

## Python implementation
Does not run without a pyhton installation and has a dependency to the cryptodome package.
Has no UI (yet?).

# CLI Interface
Usage: qryptex [option(s)]
## Options

### Encrypt
Command variants (case independent):
```
encrypt | enc
```

Options:

* -f/ --file:       Marks the text argument as path. Qryptex will then encrypt the content of the file and save as a copy of the file.
* -c/ --contact:    The contact name for which the data shall be encypted.
* -o/ --output:     The path to a directory where the encrypted data should be written to.

The command encrypts the given plaintext for the selected contact and prints it to stdout if the file flag (-f/--file) was NOT specified. Otherwise a new file next to the target is created.


### Decrypt
Command variants (case independent):
```
decrypt | dec
```

Options:

* -f/ --file:       Marks the text argument as path. Qryptex will then decrypt the content of the file.
* -o/ --output:     The path to a directory where the decrypted data should be written to.

The command decrypts the given ciphertext and prints it to stdout if the file flag (-f/--file) was NOT specified.

### Init
Command variants (case independent):
```
init
```

This command has no options or flags. It creates a .qryptex directory in the users $home and creates a keypair to use with the application.

The operation must be idempotent.

### contact add
Command variants (case independent):
```
contact add
```

Failes if there is already a contact with the same name.

### contact remove
Command variants (case independent):
```
contact remove
```

The operation must be idempotent.

### !notImplemented export {contact name}
Command variants (case independent):
```
export
```

Exports the public key of the provided contact or, if no name was given, exports the applications public key. (-t to supply a target)

# Test cases
./qryptex init
./qryptex contact add -n test1 -k ../../../dev_keys/user1/user1_pub.pem
./qryptex contact del -n test1
./qryptex enc -c test1 -t "hello world"
62F855B91F89F689CE81533DCBF0552350414043FDEE38D6CB36798E3AF63ABF97A48CCDD6572087ECB0D7716B79C1D17495952153F3DA7C9A05E7E16749882823E2D328288C50C8AB7422D179B8AC0D67781ACE36C721D584DD7E3C0F58911E7E9CA23BF6CD0C3F38DAA93C0FDB336D5ECB4E487123542D6CDB92C1A5B92750692748FEF24A1564F865BA85DBDCB1311F8FACF02C6F81D089D17A6A7BA422FD6A63DA9C9434E05805979DE55E370F5014CE6C95013972543E1EAF17BEC92E8C55637DD1DAA13EEF940916E256CD36F3D20ACDBFBE3DFB4F444F8591620EBFEFF5E4C8B141177DBF9C134BC422728B6B235242FBDD433969D37953507BF736C3

./qryptex dec -t
