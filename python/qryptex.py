from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
import sys
from pprint import *

C_COMMAND_KEY = 'command'
C_OUT_KEY = 'output'
C_FILE_FLAG_KEY = 'isfile'
C_TARGET_KEY = 'target'

data = {C_COMMAND_KEY: None, C_FILE_FLAG_KEY: False,
        C_TARGET_KEY: '', C_OUT_KEY: None, }
attr = ['-f', '-o']
enc = ['encrypt', 'e', 'enc', 'Encrypt']
dec = ['decrypt', 'd', 'dec', 'Decrypt']


# possible args
# qryptex enc ksdkjfgbnds -o c:/path/to/file.txt
# qryptex enc path/to/plain.txt -o c:/path/to/file.txt -f
# qryptex enc -f path/to/plain.txt -o c:/path/to/file.txt
# qryptex enc -o c:/path/to/file.txt -f path/to/plain.txt
def parse_cli_args():
    for i in range(1, len(sys.argv)):
        if sys.argv[i] in data.values():
            pass
        elif sys.argv[i] == 'help':
            options()
        else:
            if sys.argv[i] in attr or sys.argv[i] in enc or sys.argv[i] in dec:
                if sys.argv[i] in enc:
                    data[C_COMMAND_KEY] = 'e'
                elif sys.argv[i] in dec:
                    data[C_COMMAND_KEY] = 'd'
                elif sys.argv[i] == '-o':
                    # validate path argument
                    data[C_OUT_KEY] = sys.argv[i+1]
                elif sys.argv[i] == '-f':
                    data[C_FILE_FLAG_KEY] = True
                    data[C_TARGET_KEY] = sys.argv[i+1]
            else:

                data[C_TARGET_KEY] = sys.argv[i]

    return data


def options():
    print('possible arguments:')
    print('encrypt | enc    --> encrypts the phrase or file')
    print('decrypt | dec    --> decrypts the phrase or file')
    print('init             --> creates a .qryptex directory in the current users home directory, where contacts and the users public and private are stored. A key pair is created too.')
    print('contact add      --> adds a contact to the qryptex addressbook')
    print('contact remove   --> removes a contact from the qryptex addressbook')


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

# if setting['op'] is 'e':
#    encrypt(settings)
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

# py  qryptex.py encrypt -f C:/Testfile.py - o Testpath
