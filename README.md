# qryptex

A small encryption tool to quickly encrypt a message or file and send the result over an insecure channel.
The idea is to be able to send a password or similar over Discord for example to someone you know and not having to fight with settings.

## Rust implementation

Does not support creation and storing of a key pair. On linux we could just invoke openssl.
Has no UI (yet?).

## Python implementation

Does not run without a python installation and has a dependency to the cryptodome package.
Has no UI (yet?).

## CLI Interface

Usage: qryptex [option(s)]

### Options

#### Encrypt

Command variants (case independent):

```
encrypt | enc
```

Options:

* -f/ --file:       Marks the text argument as path.
    Qryptex will then encrypt the content of the file and save as a copy of the file.
* -c/ --contact:    The contact name for which the data shall be encypted.
* -o/ --output:     The path to a directory where the encrypted data should be written to.

The command encrypts the given plaintext for the selected contact and prints it to stdout if the file flag (-f/--file) was NOT specified. Otherwise a new file next to the target is created.

#### Decrypt

Command variants (case independent):

```bash
decrypt | dec
```

Options:

* -f/ --file:       Marks the text argument as path.
    Qryptex will then decrypt the content of the file.
* -o/ --output:     The path to a directory where the decrypted data should be written to.

The command decrypts the given ciphertext and prints it to stdout if the file flag (-f/--file) was NOT specified.

#### Init

Command variants (case independent):

```bash
init
```

This command has no options or flags. It creates a .qryptex directory in the users $home and creates a keypair to use with the application.

The operation must be idempotent.

#### contact add

Command variants (case independent):

```bash
contact add
```

Failes if there is already a contact with the same name.

#### contact remove

Command variants (case independent):

```bash
contact remove
```

The operation must be idempotent.

#### !notImplemented export {contact name}

Command variants (case independent):

```bash
export
```

Exports the public key of the provided contact or, if no name was given, exports the applications public key. (-t to supply a target)

## Test cases

### OpenSsl key pair generation

Private key

```bash
openssl genrsa --out private.pem
```

Public key

```bash
openssl rsa -in private.pem -pubout > public.pem
```

user2 keys are imported as self.
./qryptex init
./qryptex contact add -n test1 -k ../../../dev_keys/user1/user1_pub.pem
./qryptex contact del -n test1
./qryptex contact list
./qryptex contact ls
./qryptex enc -c test1 "this is a test"
cargo run -- enc -c test1 "this is a test"

