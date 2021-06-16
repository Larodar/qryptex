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
user2 keys are imported as self.
./qryptex init
./qryptex contact add -n test1 -k ../../../dev_keys/user1/user1_pub.pem
./qryptex contact del -n test1
./qryptex contact list
./qryptex contact ls
./qryptex enc -c c1 "this is a test"
ciphertext:
41130C3BCB71049E4FCA935280CBA087C90BD8992CBC5987403BE3696D97C1BB1638D239BB01DABBBEA1550BDA8CF73DE98B2993D74F92EAE73DC3723FB2C2956F2F52823AB2328E497E0E9507408C6E953AF1918CF51C50E3732D4E40A043B2DE0C5D2246CF132A5EF5957FB3449B2A0354A614DD0F49778FE671C5F1D11406E4916FFE3B1A258847B48023BAB3F7BBD43472DB03E9AC997A8CA41A8064F6BCADC728069F961B733CE6884EB5EABE3EAA8454901A60F975DB292881E43EB640D9E06FD31795403FEFE3B82CB22086BCEB269CCD96B66F76B3829287CA8F18D36A0A51AB6AA33AA8EEEBF7681F8A2B3F132071AB548373C57DA208EDF9131301
./qryptex dec 41130C3BCB71049E4FCA935280CBA087C90BD8992CBC5987403BE3696D97C1BB1638D239BB01DABBBEA1550BDA8CF73DE98B2993D74F92EAE73DC3723FB2C2956F2F52823AB2328E497E0E9507408C6E953AF1918CF51C50E3732D4E40A043B2DE0C5D2246CF132A5EF5957FB3449B2A0354A614DD0F49778FE671C5F1D11406E4916FFE3B1A258847B48023BAB3F7BBD43472DB03E9AC997A8CA41A8064F6BCADC728069F961B733CE6884EB5EABE3EAA8454901A60F975DB292881E43EB640D9E06FD31795403FEFE3B82CB22086BCEB269CCD96B66F76B3829287CA8F18D36A0A51AB6AA33AA8EEEBF7681F8A2B3F132071AB548373C57DA208EDF9131301
