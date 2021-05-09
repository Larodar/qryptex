from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
import sys
from pprint import *


def parse_cli_args():
    if sys.argv[1] == 'encrypt' or sys.argv[1] == 'enc':
        encrypt(sys.argv[2])
        print('reading plantext successful')
    elif sys.argv[1] == 'decrypt':
        decrypt(sys.argv[2])
        print('reading ciphertext successful')
    elif sys.argv[1] == 'init':
        init()
        print('building key pair successful')
    else:
        print('wrong command')

    return {'op': 'e',
            'target_is_file': True,
            'target': 'path/to/file'}


def init():
    key = RSA.generate(2048)
    f = open('private.pem', 'wb')
    f.write(key.export_key('PEM'))
    f.close()
    f = open('public.pem', 'wb')
    f.write(key.public_key().export_key('PEM'))
    f.close()


def encrypt(plaintext):
    key = RSA.import_key(open('public.pem').read())
    cipher = PKCS1_OAEP.new(key)
    ciphertext = cipher.encrypt(bytes(plaintext, 'utf-8'))
    print(ciphertext.hex())
    return ciphertext


def decrypt(ciphertext):
    key = RSA.import_key(open('private.pem').read())
    cipher = PKCS1_OAEP.new(key)
    plaintext = cipher.decrypt(bytes.fromhex(ciphertext))
    pprint(plaintext)
    # print(plaintext.decode('utf-8'))
    return plaintext


# read cli args
settings = parse_cli_args()

if setting['op'] is 'e':
    encrypt(settings)
# qryptex encrypt secretMessage
# qryptex enc secretMessage
# qryptex enc secretMessage -o path/to/output
# qryptex enc -f path/to/file
# qryptex decrypt secretMessage
# qryptex dec secretMessage

# for creating the key pair?
# qryptex init

# encrypt function
# load foreign public key
# plaintext
# build cipher object
# encrypt operation
# print ciphertext to stdout

# decrypt function
# load own private key
# ciphertext
# build cipher object
# decrypt operation
# print plaintext to stdout
