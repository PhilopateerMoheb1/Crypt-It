from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.backends import default_backend
from KeyError import KeyError
from IVError import IVError
import os
import base64

# Initialization vector (IV) for AES encryption
IV=b"0000000000000000"

def pad_with_null_bytes(data, target_length):
    # Pad the data with null bytes to reach the target length to make the last byte identified
    current_length = len(data)
    padding_size = target_length - current_length
    padding = b'\x00' * padding_size
    padded_data = data + padding
    return padded_data

def remove_null_bytes(data):
    # Check if null bytes are present
    if b'\x00' in data:
        # Remove null bytes
        data_without_null_bytes = data.replace(b'\x00', b'')
        return data_without_null_bytes
    else:
        return data  # No null bytes, return as is



def encryptAESFile(filename,key,mode="ECB",IV=b"0000000000000000"):
    # Encrypt a file using AES
    outputFile = "(enc)"+filename
    chunksize=16
    temp=""
    with open(filename, 'rb') as infile:#rb means read in binary
        with open(outputFile, 'wb') as outfile:#wb means write in the binary mode
            if(mode=="CBC"):
                while True:
                    chunk = infile.read(chunksize)
                    if not chunk:
                        break  # Break out of the loop when the end of the file is reached
                    # Pad the chunk with null bytes if its length is less than 16
                    if len(chunk)<16:
                        chunk=pad_with_null_bytes(chunk,16)
                    temp=encryptAESText(chunk,key,"CBC",IV)
                    outfile.write(temp)
            elif(mode=="ECB"):
                while True:
                    chunk = infile.read(chunksize)
                    if not chunk:
                        break 
                    # Pad the chunk with null bytes if its length is less than 16
                    if len(chunk)<16:
                        chunk=pad_with_null_bytes(chunk,16)
                    temp=encryptAESText(chunk,key) 
                    outfile.write(temp)

def decryptAESFile(filename,key,mode="ECB"):
    # Decrypt a file using AES
    outputFile = filename.replace('(enc)','')
    chunksize=32
    # outputFile = filename.replace('(dec)','')
    with open(filename, 'rb') as infile:
        if(mode=="CBC"):
            with open(outputFile, 'wb') as outfile:
                while True:
                    chunk = infile.read(chunksize)   
                    if len(chunk) == 0:
                        break
                    temp=decryptAESText(chunk,key,"CBC",IV)
                    temp=remove_null_bytes(temp)
                    outfile.write(temp)
        elif(mode=="ECB"):
            with open(outputFile, 'wb') as outfile:
                while True:
                    chunk = infile.read(chunksize)
                    if len(chunk) == 0:
                        break
                    temp=decryptAESText(chunk,key,"ECB")
                    temp=remove_null_bytes(temp)
                    outfile.write(temp)


def encryptAESText(plaintext, key,mode="ECB",IV=b"0000000000000000"):
    # Encrypt text using AES
    if(len(key)!=16 and len(key)!=24 and len(key)!=32):
        raise  KeyError("Key must have a fixed size [16,24,32]")
    if(mode=="ECB"):
        cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    elif mode=="CBC":
        if(len(IV)<16):
            raise IVError("IV must be 16 bytes long")
        cipher = Cipher(algorithms.AES(key), modes.CBC(IV), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(plaintext) + padder.finalize()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return ciphertext

def decryptAESText(ciphertext, key,mode="ECB",IV=b"0000000000000000"):
    if(len(key)!=16 and len(key)!=24 and len(key)!=32):
        raise  KeyError("Key must have a fixed size [16,24,32]")
    if(mode=="ECB"):
        cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    elif (mode=="CBC"):
        if(len(IV)<16):
            raise IVError("IV must be 16 bytes long")
        cipher = Cipher(algorithms.AES(key), modes.CBC(IV), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = PKCS7(algorithms.AES.block_size).unpadder()
    plaintext = unpadder.update(padded_data) + unpadder.finalize()
    return plaintext        

def main():
    key=b"PhiloPteer Mohebmmmmmmmmmmmmmmmm"
    print(len(key))
    choice = input("Would you like to (E)encrypt or (D)Decrypt ")
    if choice == 'E':
        choice = input("Text(T) or File(F) to encrypt: ")
        key = input("Key: ").encode()
        if(choice=="T"):
            choice=input("Mode(ECB,CBC): ")
            plaintext=input("Text: ").encode()
            if(choice=="ECB"):
                print(str(base64.b64encode(encryptAESText(plaintext,key))))
            elif(choice=="CBC"):
                print(str(base64.b64encode(encryptAESText(plaintext,key,"CBC"))))
        elif(choice=="F"):
            choice=input("Mode(ECB,CBC): ")
            filename=input("Filename: ")
            if(choice=="ECB"):
                encryptAESFile(filename,key)
            elif(choice=="CBC"):
                encryptAESFile(filename,key,"CBC")
        print('Done.')
    elif choice == 'D':
        choice = input("Text(T) or File(F) to Decrypt: ")
        key = input("Key: ").encode()
        if(choice=="T"):
            choice=input("Mode(ECB,CBC): ")
            ciphertext=input("Text: ").encode()
            ciphertext=base64.b64decode(ciphertext)
            if(choice=="ECB"):
                print(str(decryptAESText(ciphertext,key)))
            elif(choice=="CBC"):
                print(str(decryptAESText(ciphertext,key,"CBC")))
        elif(choice=="F"):
            choice=input("Mode(ECB,CBC): ")
            filename=input("Filename: ")
            if(choice=="ECB"):
                decryptAESFile(filename,key)
            elif(choice=="CBC"):
                decryptAESFile(filename,key,"CBC")
        print('Done.')
    else:
        print("No option selected, closing...")
    
main()