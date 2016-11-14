#!/usr/bin/env python
"""
Usage:
  cryptstrings listkeys
  cryptstrings createkeys [--key-name=<key_name_suffix>] [--key-size=1024] [--keys-path=<keys_path>]
  cryptstrings encrypt <filename> <attribute> [--public-key=<public-key.pem>]
  cryptstrings decrypt <filename> [--private-key=<private-key.pem>]
  cryptstrings -h | --help
  cryptstrings --version

Options:
  -h --help     Show this screen.
  --version     Show version.
"""

import os
import sys
import json,yaml
from base64 import b64decode
from distutils.util import strtobool
# import yaml
from docopt import docopt
from Crypto import Random
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP


# Constants
RSA_KEY_NAME = "cryptstrings"
RSA_PRIVATE_KEY = "_private.pem"
RSA_PUBLIC_KEY = "_public.pem"
RSA_KEYS_PATH = ".cryptstrings"
RSA_MAGIC = "MyRsa:"
RSA_KEY_SIZE=1024

PUBLIC_KEY = os.path.join(RSA_KEYS_PATH, RSA_KEY_NAME + RSA_PUBLIC_KEY)
PRIVATE_KEY = os.path.join(RSA_KEYS_PATH, RSA_KEY_NAME + RSA_PRIVATE_KEY)


def overwrite(file_name):
    exists = os.path.isfile(file_name)
    if exists:
        question = "Are you sure you want to overwrite: %s" % file_name

        sys.stdout.write('%s [y/n]\n' % question)
        while True:
            try:
                return strtobool(raw_input().lower())
            except ValueError:
                sys.stdout.write('Please respond with \'y\' or \'n\'.\n')
    else:
        return True


def ensure_dir(directory):
    print("Creating directory: %s" % directory)
    if not os.path.exists(directory):
        os.makedirs(directory, 0700)


def write_key(file_name, file_contents, key_type, keys_path):
    file_path = os.path.join(
        os.path.dirname(os.path.abspath(__file__)), keys_path)
    
    ensure_dir(file_path)
    
    if key_type == 'Private':
        file_name = file_name + RSA_PRIVATE_KEY
        print("Writing Private key: %s" % file_name)
    elif key_type == 'Public':
        file_name = file_name + RSA_PUBLIC_KEY
        print("Writing Public key: %s" % file_name)

    full_filename = os.path.join(file_path, file_name)
    print("Output to: %s" %  full_filename)

    if overwrite(full_filename):
        f = open(full_filename, 'w')
        f.write(file_contents)
        f.close()
        os.chmod(full_filename, 0400)


def create_keys(key_size=RSA_KEY_SIZE, key_name=RSA_KEY_NAME, keys_path=RSA_KEYS_PATH):
    random_generator = Random.new().read
    key = RSA.generate(key_size, random_generator)
    pub_key = key.publickey().exportKey()
    write_key(key_name, pub_key, 'Public', keys_path)
    private_key = key.exportKey()
    write_key(key_name, private_key, 'Private', keys_path)

 # magic = "MyRSA"
 # if data[:len(magic)] != magic


def process_string(attribute, command):
    print("Att:%s" % attribute)
    if command == "encrypt":
        if not attribute.startswith(RSA_MAGIC):
            #v[:len(RSA_MAGIC)] != RSA_MAGIC:
            attribute = RSA_MAGIC + encrypt_RSA(attribute)
            print("Would enc: %s" % attribute)
            return attribute

    if command == "decrypt":
        if attribute.startswith(RSA_MAGIC):
            attribute=attribute[len(RSA_MAGIC):]
            attribute=decrypt_RSA(attribute)
            return attribute

def find_key1(json_input, lookup_key, command):
    print("command: %s and lookup_key: %s" % (command,lookup_key))

def find_key(json_input, lookup_key, command):
    print("command: %s and lookup_key: %s" % (command,lookup_key))
    if isinstance(json_input, dict):
        for k, v in json_input.iteritems():
            if k == lookup_key:
                yield v
                json_input[k]=process_string(v,command)
            else:
                for child_val in find_key(v, lookup_key):
                    yield child_val
    elif isinstance(json_input, list):
        for item in json_input:
            for item_val in find_key(item, lookup_key):
                yield item_val

# https://docs.launchkey.com/developer/encryption/python/python-encryption.html
def encrypt_RSA(message,public_key=PUBLIC_KEY):
    '''
    param: public_key_loc Path to public key
    param: message String to be encrypted
    return base64 encoded encrypted string
    '''
    key = open(public_key, "r").read()
    rsakey = RSA.importKey(key)
    rsakey = PKCS1_OAEP.new(rsakey)
    encrypted = rsakey.encrypt(message)
    return encrypted.encode('base64')

# https://docs.launchkey.com/developer/encryption/python/python-encryption.html


def decrypt_RSA(package,private_key=PRIVATE_KEY):
    '''
    param: public_key_loc Path to your private key
    param: package String to be decrypted
    return decrypted string
    '''
    key = open(private_key, "r").read()
    rsakey = RSA.importKey(key)
    rsakey = PKCS1_OAEP.new(rsakey)
    decrypted = rsakey.decrypt(b64decode(package))
    return decrypted


class Dotable(dict):
    
    __getattr__ = dict.__getitem__

    def __init__(self, d):
        self.update(**dict((k, self.parse(v)) for k, v in d.iteritems()))

    @classmethod
    def parse(cls, v):
        if isinstance(v, dict):
            return cls(v)
        elif isinstance(v, list):
            return [cls.parse(i) for i in v]
        else:
            return v



if __name__ == '__main__':
    arguments = docopt(__doc__, version='0.1.1rc')
    print arguments
    # sub command
    createkeys = arguments['createkeys']

    # options
    if arguments['--key-size']:
        key_size = int(arguments['--key-size']) || RSA_KEY_SIZE
    if arguments['--key-name']:
        key_name = arguments['--key-name'] || RSA_KEY_NAME
    if arguments['--keys-path']:
        keys_path = arguments['--keys-path'] || RSA_KEYS_PATH
   
    # sub command
    encrypt =  arguments['encrypt']
   
    # sub command
    decrypt =  arguments['decrypt']

    # options

    #keys = arguments['keys']


    if createkeys:
        #create_keys(key_size, key_name, keys_path)
        create_keys(key_size, key_name, keys_path)

    if encrypt:
        filename = arguments['<filename>']
        attribute = arguments['<attribute>']
        json_data = yaml.load(open(filename,'r').read())
        #print("calling: %s" % find_key)
        find_key1(json_data, attribute, 'encrypt')
        #encrypt_values()

    if decrypt:
        filename = arguments['filename']
        pass
        #decrypt_values()
    
