# TODOs

This is a loose collection of features to implement.

## Rust implementation

|prio|name|desc|
|----|----|----|
|0|key pair creation|qryptex init should create a key pair for the application|
|1|Tests|There is no test suite. When making bigger changes, we want to ensure correctness|
|10|Release Pipeline|When the core features and tests are done, let's make a 0.1 release|
|99|UI|A simple GUI for qryptex would be cool|

## Python implementation

Does not run without a python installation and has a dependency to the cryptodome package.
Has no UI (yet?).

## Test cases

OpenSsl key pair generation:

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
