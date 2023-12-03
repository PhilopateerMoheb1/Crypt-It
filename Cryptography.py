from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.backends import default_backend
from KeyError import KeyError
from IVError import IVError
import os
import base64

def encryptAESFile(filename,key,mode="ECB",IV="0000000000000000"):
    chunksize = 16
    outputFile = "(enc)"+filename
    filesize = str(os.path.getsize(filename)).zfill(16)
    with open(filename, 'rb') as infile:#rb means read in binary
        with open(outputFile, 'wb') as outfile:#wb means write in the binary mode
            if(mode=="CBC"):
                outfile.write(filesize.encode('utf-8'))
                while True:
                    chunk = infile.read(chunksize)
                    if not chunk:
                        break  # Break out of the loop when the end of the file is reached
                    outfile.write(encryptAESText(chunk.replace('\n',''),key,"CBC",IV))
                    outfile.write(b'\n')
            elif(mode=="ECB"):
                outfile.write(filesize.encode('utf-8'))
                outfile.write('\n')
                while True:
                    chunk = infile.read(chunksize)
                    if not chunk:
                        break 
                    outfile.write(encryptAESText(chunk.replace('\n',''),key))
                    outfile.write('\n')
                
                    
def decryptAESFile(filename,key,mode="ECB"):
    chunksize = 16
    outputFile = filename.replace('(enc)','')
    # outputFile = filename.replace('(dec)','')
    with open(filename, 'rb') as infile:
        if(mode=="CBC"):
            filesize = int(infile.read(16))
            IV = infile.read(16)
            with open(outputFile, 'wb') as outfile:
                while True:
                    chunk = infile.read(chunksize)
                    if len(chunk) == 0:
                        break
                    outfile.write(decryptAESText(chunk,key,"CBC",IV).decode)
                outfile.truncate(filesize)
                    
        elif(mode=="ECB"):
            filesize = int(infile.read(16))
            with open(outputFile, 'wb') as outfile:
                while True:
                    chunk = infile.read(chunksize)
                    if len(chunk) == 0:
                        break
                    outfile.write(decryptAESText(chunk,key,"ECB"))
                outfile.truncate(filesize)


def encryptAESText(plaintext, key,mode="ECB",IV="0000000000000000"):
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
    encodedciphertext = base64.b64encode(ciphertext)
    return encodedciphertext

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
    decodedciphertext = base64.b64decode(ciphertext)
    padded_data = decryptor.update(decodedciphertext) + decryptor.finalize()
    unpadder = PKCS7(algorithms.AES.block_size).unpadder()
    plaintext = unpadder.update(padded_data) + unpadder.finalize()
    return plaintext        

def main():
    key=b"PhiloPteer Mohebmmmmmmmmmmmmmmmm"
    # choice = input("Would you like to (E)encrypt or (D)Decrypt ")
    print(len(key))
    # plaintext = input("Enter the plaintext: ").encode()
    # # iv= b'\x00' * (algorithms.AES.block_size // 8)
    iv=b"0000000000000000"
    print(iv)
    print(len(iv))
    # enc = encryptAESText(plaintext, key,"CBC",iv)
    # print("The encrypted message is :", enc)
    # dec = decryptAESText(enc, key,"CBC",iv)
    # print("The decrypted message is:", dec.decode('utf-8'))
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
                print(encryptAESFile(filename,key))
            elif(choice=="CBC"):
                IV=input("IV: ").encode()
                print(encryptAESFile(filename,key,"CBC",IV))
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
                print(dcryptAESFile(filename,key))
            elif(choice=="CBC"):
                IV=input("IV: ").encode()
                print(decryptAESFile(filename,key,"CBC"))
        print('Done.')
    else:
        print("No option selected, closing...")
    
main()