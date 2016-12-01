#!/usr/bin/env python
# Author: Uros orozel
# Company: Rackspace
"""
Usage:
  cryptstrings listkeys
  cryptstrings createkeys [--key-name=<key_name_suffix>] [--key-size=1024] [--keys-path=<keys_path>]
  cryptstrings string encrypt <input_yaml> <keyname>... [--public-key=<public-key.pem>]
  cryptstrings string decrypt <input_yaml> <keyname>... [--private-key=<private-key.pem>]
  cryptstrings file encrypt <input_file>... [--public-key=<public-key.pem>]
  cryptstrings file decrypt <input_file>... [--private-key=<private-key.pem>]
  cryptstrings -h | --help
  cryptstrings --version

Options:
  -h --help     Show this screen.
  --version     Show version.
"""

"""
http://nvie.com/posts/modifying-deeply-nested-structures/
https://gist.github.com/nvie/f304caf3b4f1ca4c3884
https://docs.launchkey.com/developer/encryption/python/python-encryption.html
http://www.blog.pythonlibrary.org/2016/05/18/python-3-an-intro-to-encryption/
https://github.com/massenz/filecrypt
"""

import os
import sys
import os.path
from os.path import expanduser
import json
import yaml
import glob
import re
from base64 import b64decode
from distutils.util import strtobool
from docopt import docopt
from Crypto import Random
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP

# PyCryptodome
# Default values
RSA_KEY_NAME = "cryptstrings"
RSA_PRIVATE_KEY = "_private.pem"
RSA_PUBLIC_KEY = "_public.pem"
RSA_KEYS = ".cryptstrings"
RSA_KEYS_PATH = os.path.join(expanduser('~'), RSA_KEYS)
RSA_MAGIC = "RSA:"
RSA_KEY_SIZE = 1024
DECRYPT_SUFF = "_decrypted"

PRIVATE_KEY = os.path.join(RSA_KEYS_PATH, RSA_KEY_NAME + RSA_PRIVATE_KEY)
PUBLIC_KEY = os.path.join(RSA_KEYS_PATH, RSA_KEY_NAME + RSA_PUBLIC_KEY)


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


def list_keys():
    private = glob.glob(RSA_KEYS_PATH + "/*" + RSA_PRIVATE_KEY)
    public = glob.glob(RSA_KEYS_PATH + "/*" + RSA_PUBLIC_KEY)
    print("\nPrivate keys:")
    for key in private:
        print(">>> %s" % key)

    print("\nPublic keys:")
    for key in public:
        print(">>> %s" % key)


def ensure_dir(directory):
    print("Creating directory: %s\n" % directory)
    if not os.path.exists(directory):
        os.makedirs(directory, 0700)


def write_key(file_name, file_contents, key_type, keys_path):
    if key_type == 'Private':
        file_name = file_name + RSA_PRIVATE_KEY
        print("Writing Private key: %s" % file_name)
    elif key_type == 'Public':
        file_name = file_name + RSA_PUBLIC_KEY
        print("Writing Public key: %s" % file_name)

    full_filename = os.path.join(file_path, file_name)
    print(">>> %s" % full_filename)

    if overwrite(full_filename):
        f = open(full_filename, 'w')
        f.write(file_contents)
        f.close()
        os.chmod(full_filename, 0400)


def write_yaml(filename, json):
    with open(filename, 'w') as outfile:
        yaml.dump(json, outfile, default_flow_style=False)


def write_file(filename, data):
    with open(filename, 'w') as outfile:
        outfile.write(data)


def create_keys(key_size=RSA_KEY_SIZE, key_name=RSA_KEY_NAME, keys_path=RSA_KEYS_PATH):
    random_generator = Random.new().read
    key = RSA.generate(key_size, random_generator)
    pub_key = key.publickey().exportKey()
    write_key(key_name, pub_key, 'Public', keys_path)
    private_key = key.exportKey()
    write_key(key_name, private_key, 'Private', keys_path)


def check_file(file_path):
    if os.path.exists(file_path):
        return True
    else:
        print("File %s doesn't exist" % file_path)
        sys.exit(1)


def load_yaml(yaml_path):
    try:
        load = yaml.load(open(yaml_path, 'r').read())
        return load
    except yaml.YAMLError as exc:
        print(exc)
        sys.exit(1)
    except IOError as e:
        print "I/O error({0}): {1} {2}".format(e.errno, e.strerror, yaml_path)
        sys.exit(1)


def load_file(file_path):
    try:
        with open(file_path, 'r') as file_data:
            load = file_data.read()
        return load
    except IOError as e:
        print "I/O error({0}): {1} {2}".format(e.errno, e.strerror, file_path)
        sys.exit(1)


def process_string(attribute):
    if encrypt:
        if not attribute.startswith(RSA_MAGIC):
            attribute = RSA_MAGIC + encrypt_RSA(attribute)
            return attribute
        else:
            return attribute

    if decrypt:
        if attribute.startswith(RSA_MAGIC):
            attribute = attribute[len(RSA_MAGIC):]
            attribute = decrypt_RSA(attribute)
            return attribute


def encrypt_RSA_file(message):
    public_key = PUBLIC_KEY
    key = open(public_key, "r").read()
    rsakey = RSA.importKey(key)
    rsakey = PKCS1_OAEP.new(rsakey)
    encrypted = rsakey.encrypt(message)
    return encrypted.encode('base64')


def encrypt_RSA_files(filename, data):
    public_key = PUBLIC_KEY
    print public_key
    with open(filename, 'w') as output_file:
        key = open(public_key, "r").read()
        session_key = Random.get_random_bytes(16)
        key = RSA.importKey(key)
        cipher_rsa = PKCS1_OAEP.new(key)
        output_file.write(cipher_rsa.encrypt(session_key))
        cipher_aes = AES.new(session_key, AES.MODE_EAX)
        ciphertext, tag = cipher_aes.encrypt_and_digest(data)

        output_file.write(cipher_aes.nonce)
        output_file.write(tag)
        output_file.write(ciphertext)


def decrypt_RSA_files(filename):
    private_key = PRIVATE_KEY
    print private_key
    with open(filename, 'rb') as fobj:
        private_key = RSA.import_key(open(private_key).read())
        enc_session_key, nonce, tag, ciphertext = [fobj.read(x)
                                                   for x in (private_key.size_in_bytes(),
                                                             16, 16, -1)]

        cipher_rsa = PKCS1_OAEP.new(private_key)
        session_key = cipher_rsa.decrypt(enc_session_key)

        cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
        data = cipher_aes.decrypt_and_verify(ciphertext, tag)
    return data


def encrypt_RSA(message):
    public_key = PUBLIC_KEY
    key = open(public_key, "r").read()
    rsakey = RSA.importKey(key)
    rsakey = PKCS1_OAEP.new(rsakey)
    encrypted = rsakey.encrypt(message)
    return encrypted.encode('base64').replace('\n', '')


def decrypt_RSA(package):
    private_key = PRIVATE_KEY
    key = open(private_key, "r").read()
    rsakey = RSA.importKey(key)
    rsakey = PKCS1_OAEP.new(rsakey)
    decrypted = rsakey.decrypt(b64decode(package))
    return decrypted


def traverse_and_modify(obj, attribute, callback, key=None):
    if isinstance(obj, dict):
        return {k: traverse_and_modify(v, attribute, callback, key=k) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [traverse_and_modify(elem, attribute, callback, key) for elem in obj]
    else:
        value = obj

    if value is None:
        return value

    reg = re.search(attribute, key)

    if reg:
        return callback(str(value))
    else:
        return value

if __name__ == '__main__':
    arguments = docopt(__doc__, version='1.0.1rc')
    

    createkeys = arguments['createkeys']
    listkeys = arguments['listkeys']
    file = arguments['file']
    string = arguments['string']
    encrypt = arguments['encrypt']
    decrypt = arguments['decrypt']

    if encrypt or decrypt:
        input_file = arguments['<input_file>']
        input_yaml = arguments['<input_yaml>']
        keyname = arguments['<keyname>']

    if createkeys:
        # options
        if arguments['--key-size']:
            key_size = int(arguments['--key-size'])
        else:
            key_size = RSA_KEY_SIZE

        if arguments['--key-name']:
            key_name = arguments['--key-name']
        else:
            key_name = RSA_KEY_NAME

        if arguments['--keys-path']:
            keys_path = arguments['--keys-path']
        else:
            keys_path = RSA_KEYS_PATH

        # os.path.abspath(__file__)
        file_path = os.path.join(expanduser('~'), keys_path)
        ensure_dir(file_path)
        create_keys(key_size, key_name, keys_path)

    if string:
        if encrypt:
            if not input_yaml.endswith(DECRYPT_SUFF):
                print(
                    "!!! WARNING !!!\nAll input files have to have a suffix: '%s' to be able filter them with gitignore etc.\n!!! WARNING !!!" % DECRYPT_SUFF)
                sys.exit(1)
            if arguments['--public-key']:
                PUBLIC_KEY = arguments['--public-key']
            check_file(PUBLIC_KEY)
            json_data = load_yaml(input_yaml)
            for key in keyname:
                json_data = traverse_and_modify(json_data, key, process_string)
            write_yaml(input_yaml[:-len(DECRYPT_SUFF)], json_data)

        if decrypt:
            if arguments['--private-key']:
                PRIVATE_KEY = arguments['--private-key']
            check_file(PRIVATE_KEY)
            json_data = load_yaml(input_yaml)

            for key in keyname:
                json_data = traverse_and_modify(json_data, key, process_string)
            write_yaml(input_yaml + DECRYPT_SUFF, json_data)

    if file:
        if encrypt:
            if arguments['--public-key']:
                PUBLIC_KEY = arguments['--public-key']
            check_file(PUBLIC_KEY)
            for file in input_file:
                if not file.endswith(DECRYPT_SUFF):
                    print(
                        "!!! WARNING !!!\nAll input files have to have a suffix: '%s' to be able filter them with gitignore etc.\n!!! WARNING !!!" % DECRYPT_SUFF)
                    sys.exit(1)
                # encrypt_file(file)
                file_data = load_file(file)
                modified = encrypt_RSA_files(
                    file[:-len(DECRYPT_SUFF)], file_data)

        if decrypt:
            if arguments['--private-key']:
                PRIVATE_KEY = arguments['--private-key']
            check_file(PRIVATE_KEY)
            for file in input_file:
                # decrypt_file(file)
                modified = decrypt_RSA_files(file)
                write_file(file + DECRYPT_SUFF, modified)

    if listkeys:
        list_keys()
