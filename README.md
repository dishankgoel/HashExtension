# Hash extension

A simple python script that implements length extension attack for SHA256


## Usage

```
➜  HashExtension git:(master) ✗ python3 hash_extension.py -h
usage: hash_extension.py [-h] -s HASH -a APPEND -k KEY_LENGTH -m MESSAGE

Tool for length extension attacks

optional arguments:
  -h, --help            show this help message and exit
  -s HASH, --hash HASH  Known hash for (secret || message)
  -a APPEND, --append APPEND
                        New message to append i.e (secret || message || append)
  -k KEY_LENGTH, --key-length KEY_LENGTH
                        Length of secret key that has been used for hashing
  -m MESSAGE, --message MESSAGE
                        Known message.
```
