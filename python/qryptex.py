import os
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
import sys
from pprint import *

C_MOD_KEY = 'module'
C_COMMAND_KEY = 'command'
C_OUT_KEY = 'output'
C_FILE_FLAG_KEY = 'isfile'
C_TARGET_KEY = 'target'
C_CONTACT_KEY = 'contact'
C_CONTACT_FLAG_KEY = 'iscontact'
C_CONTACT_COMMAND_KEY = 'Contactcommand'
C_MOD_ENC = 'encrypt'
C_MOD_DEC = 'decrypt'
C_MOD_INIT = 'init'
C_MOD_CONTACT = 'contact'
C_MOD_HELP = 'help'


# possible args
# qryptex enc ksdkjfgbnds -o c:/path/to/file.txt
# qryptex enc path/to/plain.txt -o c:/path/to/file.txt -f
# qryptex enc -f path/to/plain.txt -o c:/path/to/file.txt
# qryptex enc -o c:/path/to/file.txt -f path/to/plain.txt
# qryptex enc -o c:/path/to/destination.txt -f path/to/file.txt -c ContactName
# qryptex init
# qryptex contact remove 'contactname'
# qryptex contact add 'contactname' path/to/key.file
# qryptex enc jrgbsdijkg to 'contactname'

# parse cli args


def parse_cli_args():
    args = sys.argv
    if args[1] in ['encrypt', 'e', 'enc'] or args[1] in ['decrypt', 'd', 'dec']:
        s = {C_MOD_KEY: '', C_FILE_FLAG_KEY: False,
             C_TARGET_KEY: '', C_OUT_KEY: None, C_CONTACT_KEY: '', C_CONTACT_FLAG_KEY: False}
        if args[1] in ['encrypt', 'e', 'enc']:
            s[C_MOD_KEY] = C_MOD_ENC
        elif args[1] in ['decrypt', 'd', 'dec']:
            s[C_MOD_KEY] = C_MOD_DEC
        for i in range(2, len(args)):
            arg = args[i]
            if arg in s.values():
                pass
            elif arg is '-f':
                s[C_FILE_FLAG_KEY] = True
                s[C_TARGET_KEY] = args[i+1]
            elif arg is '-o':
                s[C_OUT_KEY] = args[i+1]
            elif arg is '-c' or arg is 'to':
                s[C_CONTACT_FLAG_KEY] = True
                s[C_CONTACT_KEY] = args[i+1]
            else:
                s[C_TARGET_KEY] = arg

    elif args[1] == 'contact':
        s = {C_MOD_KEY: '', C_TARGET_KEY: '', C_COMMAND_KEY: '', C_OUT_KEY: ''}
        s[C_MOD_KEY] = C_MOD_CONTACT
        for i in range(2, len(args)):
            arg = args[i]
            if arg is 'remove':
                s[C_COMMAND_KEY] = 'remove'
                s[C_TARGET_KEY] = args[i+1]
            elif arg is 'add':
                s[C_COMMAND_KEY] = 'add'
                s[C_TARGET_KEY] = args[i+1]
                s[C_OUT_KEY] = args[i+2]
    elif args[1] == 'init':
        s = {C_MOD_KEY: C_MOD_INIT}
    elif args[1] == 'help':
        s = {C_MOD_KEY: C_MOD_HELP}
    return s


class contact:
    def addcontact():
        directory = 'contacts'
        parent_dir = os.path.curdir
        path = os.path.join(parent_dir, directory)
        os.mkdir(path)
        os.chdir(path)

    def removecontact():
        pass

# clearifying concept of how contacts are handled
# new folder for new contact witch public.pem file inside
# or one folder with all publickey files, but files are named : contact.pem
# how are other contacts public keys initially delivered


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
    directory = 'contacts'
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


settings = parse_cli_args()

if settings[C_MOD_KEY] is C_MOD_ENC:
    encrypt(settings)
elif settings[C_MOD_KEY] is C_MOD_DEC:
    decrypt(settings)
elif settings[C_MOD_KEY] is C_MOD_CONTACT:
    contact(settings)
elif settings[C_MOD_KEY] is C_MOD_INIT:
    init()
elif settings[C_MOD_KEY] is C_MOD_HELP:
    options()
else:
    print('UNKNOWN COMMAND!\n type help for further information')


# if setting['op'] is 'e':
# encrypt(settings)
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

# py  qryptex.py encrypt -f C:/Testfile.py -o Testpath -c Testname
