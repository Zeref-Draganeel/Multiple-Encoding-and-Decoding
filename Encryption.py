import base64
from itertools import cycle
import onetimepad
import pyDes
import Crypto
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto import Random
from Crypto.Hash import SHA256
from Crypto.Cipher import AES
import sqlite3
import os
import time as t
from ast import literal_eval as e
import math

print('The following files are available :- ')
files = [f for f in os.listdir('.') if os.path.isfile(f)]
for f in files:
    print('     '+f)
while 1:
    file_name = str(input('\nWhich file do you want to open? '))
    if file_name not in files:
        print('Invalid File')
        continue
    with open(file_name,'rb') as f:
        plain = str(f.read())
    break

while 1:
    password = input('Enter your password - ')
    length = len(password)
    if length >= 8 and not length%2:
        break
    if length%2:
        print('Password should have even number of characters')
    print('Password should be more or equal to 8 characters')

print('Starting encrypting process...')
p = print

def encrypts(key, source, encode=True):
    (key,source) = (key.encode('ISO-8859-1'),source.encode('ISO-8859-1'))
    key = SHA256.new(key).digest()  
    IV = Random.new().read(AES.block_size)  
    encryptor = AES.new(key, AES.MODE_CBC, IV)
    padding = AES.block_size - len(source) % AES.block_size
    source += bytes([padding]) * padding  
    data = IV + encryptor.encrypt(source)  
    return base64.b64encode(data).decode('ISO-8859-1') if encode else data

if length > len(plain):
    length = length%len(plain)
elif length == len(plain):
    length = len(plain)//2

L0 = plain

p('Encrypting 1st level message')    
L1 = plain[length:]+plain[:length]
p(len(L1))

p('Encrypting 2nd level message')
L2 = ""
for i in range(len(L1)):
    char = L1[i]
    if (char.isupper()):
        L2 += chr((ord(char) + int(length**(6/5))))
    else:
        L2 += chr((ord(char) + int(length**(6/5))))
p(len(L2))

p('Encrypting 3rd level message')
L3 = L2.translate(str.maketrans('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz','ABCDEFGHIJKLMNOPQRSTUVWXYZ'[length:]+'ABCDEFGHIJKLMNOPQRSTUVWXYZ'[:length]+'abcdefghijklmnopqrstuvwxyz'[length:]+'abcdefghijklmnopqrstuvwxyz'[:length]))
p(len(L3))

p('Encrypting 4th level message')
L4 = [''] * length
for col in range(length):
    position = col
    while position < len(L3):
        L4[col] += L3[position]
        position += length
L4 = ''.join(L4)
p(len(L4))

p('Encrypting 5th level message')
L5 = pyDes.des(password[:8].encode('ISO-8859-1'), pyDes.CBC, b"\0\0\0\0\0\0\0\0", pad=None, padmode=pyDes.PAD_PKCS5).encrypt(L4.encode('ISO-8859-1')).decode('ISO-8859-1')
p(len(L5))

p('Encrypting 6th level message')
L6 = base64.encodebytes(''.join(chr(ord(x) ^ ord(y)) for (x,y) in zip(L5, cycle(password))).encode('ISO-8859-1')).strip().decode('ISO-8859-1')
p(len(L6))

p('Encrypting 7th level message')
L7 = encrypts(password,L6)
p(len(L7))

p('Encrypting 8th level message')
L8 = onetimepad.encrypt(L7, password)
p(len(L8))

def encrypter(char):
    return chr(((int(length**(1/3))) * ord(char) + int(str(length)[:2])) % (int(length**(4/3))**3))

p('Encrypting 9th level message')
L9 = "".join(map(encrypter, L8))
p(len(L9))

key = RSA.generate(1024, Random.new().read)
enc = PKCS1_OAEP.new(key)

to_10 = L9
to10 = []
while len(to_10)>86:
    to10.append(to_10[:86])
    to_10 = to_10[86:]
to10.append(to_10)

p('Encrypting 10th level message')
L10 = []
for x in to10:
    en = enc.encrypt(x.encode('ISO-8859-1'))
    L10.append(en)    
p(len(L10))

K0 = key.exportKey().decode('ISO-8859-1')

p('Encrypting 1st level key')    
K1 = K0[length:]+K0[:length]
p(len(K1))

p('Encrypting 2nd level key') 
K2 = ""
for i in range(len(K1)):
    char = K1[i]
    if (char.isupper()):
        K2 += chr((ord(char) + int(length**(6/5))))
    else:
        K2 += chr((ord(char) + int(length**(6/5))))
p(len(K2))

p('Encrypting 3rd level key') 
K3 = K2.translate(str.maketrans('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz','ABCDEFGHIJKLMNOPQRSTUVWXYZ'[length:]+'ABCDEFGHIJKLMNOPQRSTUVWXYZ'[:length]+'abcdefghijklmnopqrstuvwxyz'[length:]+'abcdefghijklmnopqrstuvwxyz'[:length]))
p(len(K3))

p('Encrypting 4th level key') 
K4 = [''] * length
for col in range(length):
    position = col
    while position < len(K3):
        K4[col] += K3[position]
        position += length
K4 = ''.join(K4)
p(len(K4))

p('Encrypting 5th level key') 
K5 = pyDes.des(password[:8].encode('ISO-8859-1'), pyDes.CBC, b"\0\0\0\0\0\0\0\0", pad=None, padmode=pyDes.PAD_PKCS5).encrypt(K4.encode('ISO-8859-1')).decode('ISO-8859-1')
p(len(K5))

p('Encrypting 6th level key') 
K6 = base64.encodebytes(''.join(chr(ord(x) ^ ord(y)) for (x,y) in zip(K5, cycle(password))).encode('ISO-8859-1')).strip().decode('ISO-8859-1')
p(len(K6))

p('Encrypting 7th level key')             
K7 = encrypts(password,K6)
p(len(K7))

p('Encrypting 8th level key') 
K8 = onetimepad.encrypt(K7, password)
p(len(K8))

def encrypter(char):
    return chr(((int(length**(1/3))) * ord(char) + int(str(length)[:2])) % (int(length**(4/3))**3))

p('Encrypting 9th level key') 
K9 = "".join(map(encrypter, K8))
p(len(K9))

os.system('attrib -s -h -r /s /d zerefdb.db')
conn = sqlite3.connect('zerefdb.db')
with conn:
    c = conn.cursor()
    c.execute(""" CREATE TABLE IF NOT EXISTS files (file text PRIMARY KEY, data text, key text); """)
    c.execute(''' INSERT INTO files(file,data,key) VALUES(?,?,?) ''',(file_name, str(L10), str(K9)))
os.remove(file_name)
try:
    os.system('attrib +s +h +r /s /d zerefdb.db')
except:
    pass
