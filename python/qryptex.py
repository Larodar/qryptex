from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
import sys
from pprint import *
import os

C_COMMAND_KEY = 'command'
C_OUT_KEY = 'output'
C_FILE_FLAG_KEY = 'isfile'
C_TARGET_KEY = 'target'
C_CONTACT_KEY = 'contact'
C_CONTACT_FLAG_KEY = 'iscontact'
C_CONTACT_COMMAND_KEY = 'Contactcommand'

data = {C_COMMAND_KEY: None, C_FILE_FLAG_KEY: False,
        C_TARGET_KEY: '', C_OUT_KEY: None, C_CONTACT_KEY: '', C_CONTACT_FLAG_KEY: False, C_CONTACT_COMMAND_KEY: ''}
attr = ['-f', '-o', '-c']
command = ['encrypt', 'e', 'enc', 'Encrypt', 'decrypt',
           'd', 'dec', 'Decrypt', 'help', 'add', 'remove']
# possible args
# qryptex enc ksdkjfgbnds -o c:/path/to/file.txt
# qryptex enc path/to/plain.txt -o c:/path/to/file.txt -f
# qryptex enc -f path/to/plain.txt -o c:/path/to/file.txt
# qryptex enc -o c:/path/to/file.txt -f path/to/plain.txt
# qryptex enc -o c:/path/to/destination.txt -f path/to/file.txt -c ContactName
# qryptex init -add ContactName
# qryptex remove -c ContactName


def parse_cli_args():
    for i in range(1, len(sys.argv)):
        if sys.argv[i] in data.values():
            pass
        elif sys.argv[i] in command:
            if sys.argv[i] in command[0, 3]:
                data[C_COMMAND_KEY] = 'e'
            elif sys.argv[i] in command[4, 7]:
                data[C_COMMAND_KEY] = 'd'
            elif sys.argv[i] in command[10]:
                data[C_CONTACT_COMMAND_KEY] = 'r'
            elif sys.argv[i] in command[9]:
                data[C_CONTACT_COMMAND_KEY] = 'a'
            elif sys.argv[i] in command[8]:
                data[C_COMMAND_KEY] = 'h'
        elif sys.arg[i] in attr:
            if sys.argv[i] in attr[0]:
                data[C_FILE_FLAG_KEY] = True
                data[C_TARGET_KEY] = sys.argv[i+1]
            if sys.argv[i] in attr[1]:
                data[C_OUT_KEY] = sys.argv[i+1]


# def parse_cli_args():
#    for i in range(1, len(sys.argv)):
#        if sys.argv[i] in data.values():
#            pass
#        elif sys.argv[i] == 'help':
#            options()
#        else:
#            if sys.argv[i] in attr or sys.argv[i] in enc or sys.argv[i] in dec:
#                if sys.argv[i] in enc:
#                    data[C_COMMAND_KEY] = 'e'
#                elif sys.argv[i] in dec:
#                    data[C_COMMAND_KEY] = 'd'
#                elif sys.argv[i] == '-o':
#                    # validate path argument
#                    data[C_OUT_KEY] = sys.argv[i+1]
#                elif sys.argv[i] == '-f':
#                    data[C_FILE_FLAG_KEY] = True
#                    data[C_TARGET_KEY] = sys.argv[i+1]
#            else:
#
#                data[C_TARGET_KEY] = sys.argv[i]
#
#    return data


def options():
    print('possible arguments:')
    print('________________________________________________________________')
    print('encrypt | enc    --> encrypts the phrase or file')
    print('decrypt | dec    --> decrypts the phrase or file')
    print('-f               --> used to mark file, then enter path to file e.g.: \n \t\t     -f C:/folder/file.txt\n')
    print('-o               --> used to mark output path e.g.: \n \t\t     -o C:/folder/destination.txt\n')
    print('-c               --> used to mark contactname e.g.: \n \t\t     -c Contactname\n')
    print('init             --> creates a .qryptex directory in the current users home directory,\n \t\t     where contacts and the users public and private are stored.\n \t\t     A key pair is created too.\n')
    print('add              --> adds a contact to the qryptex addressbook e.g.: \n \t\t     init add -c Contactname\n')
    print('remove           --> removes a contact from the qryptex addressbook e.g.: \n \t\t     qryptex.py remove -c Username\n')


def init():
    directory = data[C_CONTACT_KEY]
    parent_dir = os.path.curdir
    path = os.path.join(parent_dir, directory)
    os.mkdir(path)
    os.chdir(path)
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
