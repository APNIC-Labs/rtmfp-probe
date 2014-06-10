#!/usr/bin/env python

from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256

DEFAULT_KEY='\x41\x64\x6F\x62\x65\x20\x53\x79\x73\x74\x65\x6D\x73\x20\x30\x32'

def encrypt(block, key):
    obj = AES.new(key, AES.MODE_CBC, '\x00'*16)
    return obj.encrypt(block)

def decrypt(block, key):
    obj = AES.new(key, AES.MODE_CBC, '\x00'*16)
    return obj.decrypt(block)

def makeKeys(sknc, skfc, shared):
    tmp = HMAC.new(skfc, sknc, SHA256).digest()
    encryptKey = HMAC.new(shared, tmp, SHA256).digest()
    tmp = HMAC.new(sknc, skfc, SHA256).digest()
    decryptKey = HMAC.new(shared, tmp, SHA256).digest()

    return (encryptKey[:16], decryptKey[:16])
