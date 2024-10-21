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

<br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br>




































































//Write a program to implement the Diffie-Hellman Key Exchange algorithm <br>
<br>
pip install cryptography <br>
<br>
from cryptography.hazmat.backends import default_backend <br>
from cryptography.hazmat.primitives.asymmetric import dh <br>
from cryptography.hazmat.primitives import hashes <br>
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt <br>
parameters = dh.generate_parameters(generator=2, key_size=2048, <br>
backend=default_backend()) <br>
kedar_private_key = parameters.generate_private_key() <br>
damale_private_key = parameters.generate_private_key() <br>
kedar_public_key = kedar_private_key.public_key() <br>
damale_public_key = damale_private_key.public_key() <br>
kedar_shared_key = kedar_private_key.exchange(damale_public_key) <br>
damale_shared_key = damale_private_key.exchange(kedar_public_key) <br>
def derive_key(shared_key): <br>
 kdf = Scrypt(salt=b'salt', length=32, n=2**14, r=8, p=1, <br>
backend=default_backend()) <br>
 return kdf.derive(shared_key) <br>
kedar_symmetric_key = derive_key(kedar_shared_key) <br>
damale_symmetric_key = derive_key(damale_shared_key) <br>
print(f"Kedar's Symmetric Key: {kedar_symmetric_key.hex()}") <br>
print(f"Damale's Symmetric Key: {damale_symmetric_key.hex()}") <br>



//Write a program to implement DES algorithm 
<br>
pip install pycryptodome 
<br>
from Crypto.Cipher import DES <br>
from Crypto.Util.Padding import pad, unpad <br>
import binascii <br>
def des_encrypt(plaintext, key): <br>
 cipher = DES.new(key, DES.MODE_CBC) <br>
 padded_plaintext = pad(plaintext.encode('utf-8'), DES.block_size) <br>
 ciphertext = cipher.encrypt(padded_plaintext) <br>
 return binascii.hexlify(cipher.iv + ciphertext).decode('utf-8') <br>
def des_decrypt(ciphertext_hex, key): <br>
 ciphertext = binascii.unhexlify(ciphertext_hex) <br>
 iv = ciphertext[:DES.block_size] <br>
 ciphertext = ciphertext[DES.block_size:] <br>
 cipher = DES.new(key, DES.MODE_CBC, iv) <br>
 padded_plaintext = cipher.decrypt(ciphertext) <br>
 plaintext = unpad(padded_plaintext, DES.block_size).decode('utf-8') <br>
 return plaintext <br>
key = b'abcdefgh' plaintext = "KedarDamale" <br>
ciphertext = des_encrypt(plaintext, key) <br>
print(f"Encrypted: {ciphertext}") <br>
decrypted_text = des_decrypt(ciphertext, key) <br>
print(f"Decrypted: {decrypted_text}") <br>



//Write a program to implement the RSA algorithm
<br>
pip install pycryptodome 
<br>
from Crypto.Util.number import getPrime, inverse <br>
import random <br>
def generate_keypair(bits=1024): <br>
 p = getPrime(bits) <br>
 q = getPrime(bits) <br>
 n = p * q <br>
 phi = (p - 1) * (q - 1) <br>
 e = 65537 <br>
 d = inverse(e, phi) <br>
 return ((e, n), (d, n)) <br>
def encrypt(public_key, plaintext): <br>
 e, n = public_key <br> 
 cipher = [pow(ord(char), e, n) for char in plaintext] <br>
 return cipher <br>
def decrypt(private_key, ciphertext): <br>
 d, n = private_key <br>
 plain = [chr(pow(char, d, n)) for char in ciphertext] <br>
 return ''.join(plain) <br>
public_key, private_key = generate_keypair() <br>
message = "KedarDamale" <br>
encrypted_message = encrypt(public_key, message) <br>
decrypted_message = decrypt(private_key, encrypted_message) <br>
print(f"Original message: {message}") <br>
print(f"Encrypted message: {encrypted_message}") <br>
print(f"Decrypted message: {decrypted_message}") <br>



//Write a program to implement the Playfair cipher using SubsƟtuƟon technique.
<br>
import numpy as np
<br>
def playfair_cipher(text, key): <br>
key = ''.join(sorted(set(key.replace('J', 'I')), key=key.index)) <br>
 alphabet = 'ABCDEFGHIKLMNOPQRSTUVWXYZ' <br>
key += ''.join(filter(lambda c: c not in key, alphabet)) <br>
 matrix = np.array(list(key)).reshape(5, 5) <br>
 def get_pos(char): <br>
 pos = np.argwhere(matrix == char) <br>
 return pos[0] if pos.size else None <br>
 def encode_pair(a, b): <br>
 pos_a, pos_b = get_pos(a), get_pos(b) <br>
 if pos_a is None or pos_b is None: <br>
 return a + b <br>
 if pos_a[0] == pos_b[0]: <br> 
 return matrix[pos_a[0], (pos_a[1] + 1) % 5] + matrix[pos_b[0], <br>
(pos_b[1] + 1) % 5] <br>
 if pos_a[1] == pos_b[1]: <br>
 return matrix[(pos_a[0] + 1) % 5, pos_a[1]] + matrix[(pos_b[0] + 1) % <br> 
5, pos_b[1]] <br>
 return matrix[pos_a[0], pos_b[1]] + matrix[pos_b[0], pos_a[1]] <br>
text = text.replace('J', 'I').upper().replace(' ', '') <br>
 if len(text) % 2 != 0: <br>
text += 'X' <br>
 return ''.join(encode_pair(a, b) for a, b in zip(text[::2], text[1::2])) <br>
text = "KedarDamale" <br>
key = "KEYWORD" <br>
print(playfair_cipher(text, key) <br>
