# Practical_Exam
Hello <br>
This is the content before updating the file
Date: 21-10-2024 
Time: 12:00 PM

Name: Suyog Sandip Patil
Roll No: 58
Batch: B4
Class: TEIT
This is the content after updating the file
Date: 21-10-2024
Time: 12:05 PM






































































//Write a program to implement the Diffie-Hellman Key Exchange algorithm 

pip install cryptography 

from cryptography.hazmat.backends import default_backend 
from cryptography.hazmat.primitives.asymmetric import dh 
from cryptography.hazmat.primitives import hashes 
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt 
parameters = dh.generate_parameters(generator=2, key_size=2048, 
backend=default_backend()) 
kedar_private_key = parameters.generate_private_key() 
damale_private_key = parameters.generate_private_key() 
kedar_public_key = kedar_private_key.public_key() 
damale_public_key = damale_private_key.public_key() 
kedar_shared_key = kedar_private_key.exchange(damale_public_key) 
damale_shared_key = damale_private_key.exchange(kedar_public_key) 
def derive_key(shared_key): 
 kdf = Scrypt(salt=b'salt', length=32, n=2**14, r=8, p=1, 
backend=default_backend()) 
 return kdf.derive(shared_key) 
kedar_symmetric_key = derive_key(kedar_shared_key) 
damale_symmetric_key = derive_key(damale_shared_key) 
print(f"Kedar's Symmetric Key: {kedar_symmetric_key.hex()}") 
print(f"Damale's Symmetric Key: {damale_symmetric_key.hex()}") 



//Write a program to implement DES algorithm

pip install pycryptodome

from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad
import binascii
def des_encrypt(plaintext, key):
 cipher = DES.new(key, DES.MODE_CBC)
 padded_plaintext = pad(plaintext.encode('utf-8'), DES.block_size)
 ciphertext = cipher.encrypt(padded_plaintext)
 return binascii.hexlify(cipher.iv + ciphertext).decode('uƞ-8')
def des_decrypt(ciphertext_hex, key):
 ciphertext = binascii.unhexlify(ciphertext_hex)
 iv = ciphertext[:DES.block_size]
 ciphertext = ciphertext[DES.block_size:]
 cipher = DES.new(key, DES.MODE_CBC, iv)
 padded_plaintext = cipher.decrypt(ciphertext)
 plaintext = unpad(padded_plaintext, DES.block_size).decode('uƞ-8')
 return plaintext
key = b'abcdefgh' plaintext = "KedarDamale"
ciphertext = des_encrypt(plaintext, key)
print(f"Encrypted: {ciphertext}")
decrypted_text = des_decrypt(ciphertext, key)
print(f"Decrypted: {decrypted_text}")



//Write a program to implement the RSA algorithm

pip install pycryptodome 

from Crypto.Util.number import getPrime, inverse
import random
def generate_keypair(bits=1024):
 p = getPrime(bits)
 q = getPrime(bits)
 n = p * q
 phi = (p - 1) * (q - 1)
 e = 65537 
 d = inverse(e, phi)
 return ((e, n), (d, n))
def encrypt(public_key, plaintext):
 e, n = public_key
 cipher = [pow(ord(char), e, n) for char in plaintext]
 return cipher
def decrypt(private_key, ciphertext):
 d, n = private_key
 plain = [chr(pow(char, d, n)) for char in ciphertext]
 return ''.join(plain)
public_key, private_key = generate_keypair()
message = "KedarDamale"
encrypted_message = encrypt(public_key, message)
decrypted_message = decrypt(private_key, encrypted_message)
print(f"Original message: {message}")
print(f"Encrypted message: {encrypted_message}")
print(f"Decrypted message: {decrypted_message}")



//Write a program to implement the Playfair cipher using SubsƟtuƟon technique.

import numpy as np

def playfair_cipher(text, key):
key = ''.join(sorted(set(key.replace('J', 'I')), key=key.index))
 alphabet = 'ABCDEFGHIKLMNOPQRSTUVWXYZ'
key += ''.join(filter(lambda c: c not in key, alphabet))
 matrix = np.array(list(key)).reshape(5, 5)
 def get_pos(char):
 pos = np.argwhere(matrix == char)
 return pos[0] if pos.size else None
 def encode_pair(a, b):
 pos_a, pos_b = get_pos(a), get_pos(b)
 if pos_a is None or pos_b is None:
 return a + b
 if pos_a[0] == pos_b[0]: 
 return matrix[pos_a[0], (pos_a[1] + 1) % 5] + matrix[pos_b[0], 
(pos_b[1] + 1) % 5]
 if pos_a[1] == pos_b[1]: 
 return matrix[(pos_a[0] + 1) % 5, pos_a[1]] + matrix[(pos_b[0] + 1) % 
5, pos_b[1]]
 return matrix[pos_a[0], pos_b[1]] + matrix[pos_b[0], pos_a[1]] 
text = text.replace('J', 'I').upper().replace(' ', '')
 if len(text) % 2 != 0:
text += 'X' 
 return ''.join(encode_pair(a, b) for a, b in zip(text[::2], text[1::2]))
text = "KedarDamale"
key = "KEYWORD"
print(playfair_cipher(text, key)
