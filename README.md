# qryptex
![rust main](https://github.com/Larodar/qryptex/actions/workflows/rust.yml/badge.svg)

A small encryption tool to quickly encrypt a message or file and send the result over an insecure channel (Discord, Slack, etc).
The idea is to be able to send a password or files containing sensitive data to someone you know and not having to fight with settings or worry about the channel.

## Usage

Usage: qryptex [option(s)]

### Encrypt

Command variants (case independent):

```
encrypt | enc
```

Options:

* -f/ --file:       Marks the text argument as path.
    Qryptex will then encrypt the content of the file and save it as a copy of the file.
* -c/ --contact:    The contact name for which the data shall be encypted.
* -o/ --output:     The path to a directory where the encrypted data should be written to.

The command encrypts the given plaintext for the selected contact and prints it to stdout if the file flag (-f/--file) was NOT specified. Otherwise a new file next to the target is created.

### Decrypt

Command variants (case independent):

```bash
decrypt | dec
```

Options:

* -f/ --file:       Marks the text argument as path.
    Qryptex will then decrypt the content of the file.
* -o/ --output:     The path to a directory where the decrypted data should be written to.

The command decrypts the given ciphertext and prints it to stdout if the file flag (-f/--file) was NOT specified.

### Init

Command variants (case independent):

```bash
init
```

This command has no options or flags. It creates a .qryptex directory in the users $home and creates a keypair to use with the application.
If the directory does already exist, nothing is changed.

## Contacts

A contact is a file containing the public key against which to encrypt.
They are stored in *~/.qryptex/contacts/*. The name of the contact acts as a key to load the cryptographic key for the encryption operations.

### contact add

Command variants (case independent):

```bash
contact add -n name -k path/to/key.pem
contact add -name name -key path/to/key.pem
```

This command fails if there is already a contact with the same name.

### contact remove

Command variants (case independent):

```bash
contact remove --name name
contact rem -n name
contact delete --name name
contact del -n name
```

### contact list

Prints a list of the available contacts.

```bash
contact list
```

### export key

Command variants (case independent):

Export the applications public key, which you can send to someone,
you want to exchange data with.

```bash
export -t ~/path/to/key.pem
export --target ~/path/to/key.pem
```

Export the public key of a contact.

```bash
export -t ~/path/to/key.pem
export --target ~/path/to/key.pem
```

Exports the public key of the provided contact or,
if no name was given, exports the applications public key. (-t to supply a target)

### Misc

There is a *--debug* flag implemented, which switches the qryptex home dir to .qryptex_dev.
The implementation is a quickfix. Expect it to not work properly.
