#!/usr/bin/python
from Crypto.Cipher import AES
import os
import sys
import re

class Authenticator:
    def __init__(self):
        '''Securely generate the key and initialization vector from os.urandom'''
        self.blocksize = 16
        self.key = os.urandom(self.blocksize)
        self.iv = os.urandom(self.blocksize)
        
    def _pad(self, unpadded):
        '''Pad a string with the PKCS 7 Standard'''
        padbyte = self.blocksize - (len(unpadded) % self.blocksize)
        return unpadded + (chr(padbyte) * padbyte)

    def _unpad(self, padded):
        '''Unpad a string padded with the PKCS 7 Standard'''
        padbyte = padded[-1]
        return padded[:-ord(padbyte)]

    def parse_input(self):
        '''Parse user input removing all non-alphanumeric characters'''
        input = sys.stdin.readline()
        return re.sub('[\W_]','',input)

    def authenticate(self):
        '''Allow user "login"'''
        print "Enter your username: ",
        username = self.parse_input()
        print "Enter your password: ",
        password = self.parse_input()
        crypt = AES.new(self.key,AES.MODE_CBC,self.iv)
        plaintoken = self._pad("u:" + username + ";p:" + password + ";g:user")
        print "Your access token:"
        return (self.iv + crypt.encrypt(plaintoken)).encode('hex')

    def check_group(self):
        '''Check the access token for group permissions'''
        print "Enter your access token:"
        crypttoken = self.parse_input()
        if (len(crypttoken) < 32) or (len(crypttoken) % 32 != 0):
            print "Bad Access Token"
            return False
        crypttoken = crypttoken.decode('hex')
        iv = crypttoken[:16]
        plaintoken = crypttoken[16:]
        crypt = AES.new(self.key, AES.MODE_CBC, iv)
        plaintoken = crypt.decrypt(plaintoken)
        fields = self._unpad(plaintoken).split(';')
        for item in fields:
            field = item.split(':')
            if field[0] == 'g' and field[1] == 'admin':
                return True
        return False

    def login(self):
        '''Check if the user is an admin'''
        if self.check_group():
            print 'Welcome Admin!'
            return True
        print 'Welcome User!'
        return False

auth = Authenticator()
print auth.authenticate()

count = 10
for x in range(0, count):
    if auth.login():
        break
    print str(count - x - 1) + " attempts left"
