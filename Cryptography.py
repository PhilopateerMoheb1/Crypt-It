from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.backends import default_backend
from KeyError import KeyError
from IVError import IVError
import os
import base64


IV=b"0000000000000000"

def pad_with_null_bytes(data, target_length):
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



def encryptAESFile(filename,key,mode="ECB",IV="0000000000000000"):
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
                    if len(chunk)<16:
                        chunk=pad_with_null_bytes(chunk,16)
                    temp=encryptAESText(chunk,key,"CBC",IV)
                    outfile.write(temp)
            elif(mode=="ECB"):
                while True:
                    chunk = infile.read(chunksize)
                    if not chunk:
                        break 
                    if len(chunk)<16:
                        chunk=pad_with_null_bytes(chunk,16)
                    temp=encryptAESText(chunk,key) 
                    outfile.write(temp)
def decryptAESFile(filename,key,mode="ECB"):
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


def encryptAESText(plaintext, key,mode="ECB",IV="0000000000000000",lastByte=False):
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

def is_last_byte_contained(data, values):
    if not data:
        return False  # Ensure the data is not empty

    last_byte = data[-1]
    return last_byte in values


def decryptAESText(ciphertext, key,mode="ECB",IV="0000000000000000"):
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
                print(encryptAESText(plaintext,key))
            elif(choice=="CBC"):
                IV=input("IV: ").encode()
                print(encryptAESText(plaintext,key,"CBC",IV))
        elif(choice=="F"):
            choice=input("Mode(ECB,CBC): ")
            filename=input("Filename: ")
            if(choice=="ECB"):
                encryptAESFile(filename,key)
            elif(choice=="CBC"):
                IV=input("IV: ").encode()
                encryptAESFile(filename,key,"CBC",IV)
        print('Done.')
    elif choice == 'D':
        choice = input("Text(T) or File(F) to Decrypt: ")
        key = input("Key: ").encode()
        if(choice=="T"):
            choice=input("Mode(ECB,CBC): ")
            ciphertext=input("Text: ").encode()
            if(choice=="ECB"):
                print(decryptAESText(ciphertext,key))
            elif(choice=="CBC"):
                IV=input("IV: ").encode()
                print(decryptAESText(plaintext,key,"CBC",IV))
        elif(choice=="F"):
            choice=input("Mode(ECB,CBC): ")
            filename=input("Filename: ")
            if(choice=="ECB"):
                decryptAESFile(filename,key)
            elif(choice=="CBC"):
                IV=input("IV: ").encode()
                decryptAESFile(filename,key,"CBC")
        print('Done.')
    else:
        print("No option selected, closing...")
    
main()