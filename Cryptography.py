from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os
import base64
import sys
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC



salt=b'B\xe37hN?]\xee}\xe0\x80\xbejT\xcf\xeb\xa1\x90\xf9z\xba\\|\xd9\xc5m\x89\xb5\x87\xdc}\xb5'
password=b'30C&%U`j07hj'


def encryptAES(plaintext,key=0,mode="ECB"):
    if(key==0):
        kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=480000,
        )
        key = kdf.derive(password)
        
    if len(key) not in [16, 24, 32]:
        raise ValueError("Invalid key length. Key must be 16, 24, or 32 bytes.")
    if(mode=="ECB"):
        cipher=Cipher(algorithms.AES(key), modes.ECB(),backend=default_backend())
        encryptor = cipher.encryptor()
        padder = PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(plaintext) + padder.finalize()
        # Encrypt the message
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        return ciphertext
def decryptAES(ciphertext,key=0,mode="ECB"):
     if(key==0):
        kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=480000,
        )
        key = kdf.derive(password)
     if len(key) not in [16, 24, 32]:
        raise ValueError("Invalid key length. Key must be 16, 24, or 32 bytes.")
     if(mode=="ECB"):
        cipher=Cipher(algorithms.AES(key), modes.ECB(),backend=default_backend())
        decryptor = cipher.decryptor()
        decodedciphertext = base64.b64decode(ciphertext)
        padded_data = decryptor.update(decodedciphertext) + decryptor.finalize()
        unPadder = PKCS7(algorithms.AES.block_size).unpadder()
        # Decrypt the message
        plaintext = unPadder.update(padded_data) + unPadder.finalize()
        return plaintext
    

plaintext=b"Hello Secret World!"

print("Cipher Text: "+str(encryptAES(plaintext)))
print("Plain Text: "+str(decryptAES(encryptAES(plaintext))))
