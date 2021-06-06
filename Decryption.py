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
import math
import time as t
from ast import literal_eval as e

file_list = {}
data_list = {}
password_list = {}

os.system('attrib -s -h -r /s /d zerefdb.db')
conn = sqlite3.connect('zerefdb.db')
c = conn.cursor()
c.execute(""" CREATE TABLE IF NOT EXISTS files (file text PRIMARY KEY, data text, key text); """)
c.execute("SELECT * FROM files")
rows = c.fetchall()
i = 0
print('The following files are available')
for row in rows:
    file_list[row[0]] = i
    print(row[0])
    data_list[i] = row[1]
    password_list[i] = row[2]
while 1:
    file = input('Which file do you want to open? ')
    if file not in file_list:
        print('Invalid File')
        continue
    break
num = file_list[file]
data = e(data_list[num])
keypassword = password_list[num]
while 1:
    password = input('Please enter your password - ')
    length = len(password)
    if length >= 8 and not length%2:
        break
    if length%2:
        print('Password will have even number of characters')
    print('Password will be more or equal to 8 characters')
print('Starting decrypting process...')
p = print
try:
    def decrypts(key, source, decode=True):
        key=key.encode('ISO-8859-1')
        if decode:
            source = base64.b64decode(source.encode("latin-1"))
        key = SHA256.new(key).digest()  
        IV = source[:AES.block_size]  
        decryptor = AES.new(key, AES.MODE_CBC, IV)
        data = decryptor.decrypt(source[AES.block_size:])  
        padding = data[-1]  
        if data[-padding:] != bytes([padding]) * padding:  
            raise ValueError("Invalid padding...")
        return data[:-padding].decode('ISO-8859-1')

    p('Taking 9th level key...')
    K92 = keypassword
    p(len(K92))

    def modInverse(a, m) : 
        a = a % m
        for x in range(1, m): 
            if ((a * x) % m == 1): 
                return x 
        return 1

    def decrypter(char):
          return chr(modInverse((int(length**(1/3))), (int(length**(4/3))**3)) * (ord(char) - int(str(length)[:2])) % (int(length**(4/3))**3))

    p('Decrypting 9th level key...')
    K82 = "".join(map(decrypter, K92))
    p(len(K82))

    p('Decrypting 8th level key...')
    K72 = onetimepad.decrypt(K82, password)
    p(len(K72))

    p('Decrypting 7th level key...')
    K62 = decrypts(password,K72)
    p(len(K62))

    p('Decrypting 6th level key...')
    K52 = ''.join(chr(ord(x) ^ ord(y)) for (x,y) in zip(base64.decodebytes(K62.encode('ISO-8859-1')).decode('ISO-8859-1'), cycle(password)))
    p(len(K52))

    p('Decrypting 5th level key...')
    K42 = pyDes.des(password[:8].encode('ISO-8859-1'), pyDes.CBC, b"\0\0\0\0\0\0\0\0", pad=None, padmode=pyDes.PAD_PKCS5).decrypt(K52.encode('ISO-8859-1')).decode('ISO-8859-1')
    p(len(K42))

    p('Decrypting 3rd level key...')
    numOfColumns = math.ceil(len(K42) / length)
    numOfRows = length
    numOfShadedBoxes = (numOfColumns * numOfRows) - len(K42)
    plaintext = [''] * numOfColumns
    col = 0
    row = 0
    for symbol in K42:
      plaintext[col] += symbol
      col += 1
      if (col == numOfColumns) or (col == numOfColumns - 1 and row >= numOfRows - numOfShadedBoxes):
         col = 0
         row += 1
    K32 = ''.join(plaintext)
    p(len(K32))

    p('Decrypting 2nd level key...')
    K22 = K32.translate(str.maketrans('ABCDEFGHIJKLMNOPQRSTUVWXYZ'[length:]+'ABCDEFGHIJKLMNOPQRSTUVWXYZ'[:length]+'abcdefghijklmnopqrstuvwxyz'[length:]+'abcdefghijklmnopqrstuvwxyz'[:length],'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'))
    p(len(K22))

    p('Decrypting 1st level key...')
    K12 = ""
    for i in range(len(K22)):
        char = K22[i]
        if (char.isupper()):
            K12 += chr((ord(char) - int(length**(6/5))))
        else:
            K12 += chr((ord(char) - int(length**(6/5))))
    p(len(K12))

    p('Decrypting key...')
    K02 = K12[-1*length:]+K12[:-1*length]
    p(len(K02))

    p('Getting key...')
    key = RSA.importKey(K02)
    enc = PKCS1_OAEP.new(key)

    p('Taking 10th level message...')
    p(len(data))
    L102 = []
    for x in data:
        de = enc.decrypt(x)
        L102.append(de.decode('ISO-8859-1'))
    p(len(L102))

    p('Decrypting 10th level message...')
    L92 = ''.join(L102)
    p(len(L92))
    
    def decrypter(char):
          return chr(modInverse((int(length**(1/3))), (int(length**(4/3))**3)) * (ord(char) - int(str(length)[:2])) % (int(length**(4/3))**3))

    p('Decrypting 9th level message...')
    L82 = "".join(map(decrypter, L92))
    p(len(L82))

    p('Decrypting 8th level message...')
    L72 = onetimepad.decrypt(L82, password)
    p(len(L72))

    p('Decrypting 7th level message...')
    L62 = decrypts(password,L72)
    p(len(L62))

    p('Decrypting 6th level message...')
    L52 = ''.join(chr(ord(x) ^ ord(y)) for (x,y) in zip(base64.decodebytes(L62.encode('ISO-8859-1')).decode('ISO-8859-1'), cycle(password)))
    p(len(L52))

    p('Decrypting 5th level message...')
    L42 = pyDes.des(password[:8].encode('ISO-8859-1'), pyDes.CBC, b"\0\0\0\0\0\0\0\0", pad=None, padmode=pyDes.PAD_PKCS5).decrypt(L52.encode('ISO-8859-1')).decode('ISO-8859-1')
    p(len(L42))

    p('Decrypting 4th level message...')
    numOfColumns = math.ceil(len(L42) / length)
    numOfRows = length
    numOfShadedBoxes = (numOfColumns * numOfRows) - len(L42)
    plaintext = [''] * numOfColumns
    col = 0
    row = 0
    for symbol in L42:
      plaintext[col] += symbol
      col += 1
      if (col == numOfColumns) or (col == numOfColumns - 1 and row >= numOfRows - numOfShadedBoxes):
         col = 0
         row += 1
    L32 = ''.join(plaintext)
    p(len(L32))

    p('Decrypting 3rd level message...')
    L22 = L32.translate(str.maketrans('ABCDEFGHIJKLMNOPQRSTUVWXYZ'[length:]+'ABCDEFGHIJKLMNOPQRSTUVWXYZ'[:length]+'abcdefghijklmnopqrstuvwxyz'[length:]+'abcdefghijklmnopqrstuvwxyz'[:length],'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'))
    p(len(L22))

    p('Decrypting 2nd level message...')
    L12 = ""
    for i in range(len(L22)):
        char = L22[i]
        if (char.isupper()):
            L12 += chr((ord(char) - int(length**(6/5))))
        else:
            L12 += chr((ord(char) - int(length**(6/5))))
    p(len(L12))

    p('Decrypting 1st level message...')
    L02 = L12[-1*length:]+L12[:-1*length]
    p(len(L02))

    p('Writing to file..')
    p(len(e(L02)))
    with open(file,'wb+') as f:
        f.write(e(L02))
    t.sleep(1)
    c.execute('DELETE from files where file = ?', (file, ))
    conn.commit()

except Exception as e:
    print(e)
    print('Incorrect password!! ')
    
finally:
    os.system('attrib +s +h +r /s /d zerefdb.db')
    c.close()
    conn.close()
