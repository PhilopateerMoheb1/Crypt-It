from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.backends import default_backend
from KeyError import KeyError
from IVError import IVError
import os
import base64

# Initialization vector (IV) for AES encryption
IV = b"0000000000000000"


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


def remove_pkcs7_padding(data):
    if not data:
        return b''  # Ensure the data is not empty

    # Get the last byte, which represents the number of padding bytes
    last_byte = data[-1]

    # Check if the padding is valid
    if 1 <= last_byte <= len(data):
        # Check if the last 'last_byte' bytes are equal to the padding value
        if all(byte == last_byte for byte in data[-last_byte:]):
            # Remove the padding bytes
            return data[:-last_byte]

    # If the padding is not valid, return the original data
    return data


def encryptAESFile(filename, key, mode="ECB", IV=b"0000000000000000"):
    # Encrypt a file using AES
    outputFile = "(enc)" + filename
    chunksize = 16
    temp = ""
    with open(filename, 'rb') as infile:  # rb means read in binary
        with open(outputFile, 'wb') as outfile:  # wb means write in the binary mode
            if (mode == "CBC"):
                while True:
                    chunk = infile.read(chunksize)
                    if not chunk:
                        break  # Break out of the loop when the end of the file is reached
                    temp = encryptAESText(chunk, key, "CBC", IV)
                    outfile.write(temp)
            elif (mode == "ECB"):
                while True:
                    chunk = infile.read(chunksize)
                    if not chunk:
                        break
                    temp = encryptAESText(chunk, key)
                    outfile.write(temp)


def decryptAESFile(filename, key, mode="ECB"):
    # Decrypt a file using AES
    outputFile = filename.replace('(enc)', '')
    chunksize = 16
    with open(filename, 'rb') as infile:
        if (mode == "CBC"):
            with open(outputFile, 'wb') as outfile:
                while True:
                    chunk = infile.read(chunksize)
                    if len(chunk) == 0:
                        break
                    temp = decryptAESText(chunk, key, "CBC", IV)
                    outfile.write(temp)
        elif (mode == "ECB"):
            with open(outputFile, 'wb') as outfile:
                while True:
                    chunk = infile.read(chunksize)
                    if len(chunk) == 0:
                        break
                    temp = decryptAESText(chunk, key, "ECB")
                    outfile.write(temp)


def encryptAESText(plaintext, key, mode="ECB", IV=b"0000000000000000"):
    ciphertext = ""
    # Encrypt text using AES
    if (len(key) != 16 and len(key) != 24 and len(key) != 32):
        raise KeyError("Key must have a fixed size [16,24,32]")
    if (mode == "ECB"):
        cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    elif mode == "CBC":
        if (len(IV) < 16):
            raise IVError("IV must be 16 bytes long")
        cipher = Cipher(algorithms.AES(key), modes.CBC(IV), backend=default_backend())
    encryptor = cipher.encryptor()
    # Pad the chunk with null bytes if its length is less than 16
    if len(plaintext) < 16:
        padder = PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(plaintext) + padder.finalize()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    else:
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    return ciphertext


def decryptAESText(ciphertext, key, mode="ECB", IV=b"0000000000000000"):
    if (len(key) != 16 and len(key) != 24 and len(key) != 32):
        raise KeyError("Key must have a fixed size [16,24,32]")
    if (mode == "ECB"):
        cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    elif (mode == "CBC"):
        if (len(IV) < 16):
            raise IVError("IV must be 16 bytes long")
        cipher = Cipher(algorithms.AES(key), modes.CBC(IV), backend=default_backend())
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    plaintext = remove_pkcs7_padding(plaintext)
    return plaintext


def main():
    key = b"PhiloPteer Mohebmmmmmmmmmmmmmmmm"
    print(len(key))
    choice = input("Would you like to (E)encrypt or (D)Decrypt ")
    if choice == 'E':
        choice = input("Text(T) or File(F) to encrypt: ")
        key = input("Key: ").encode()
        if (choice == "T"):
            choice = input("Mode(ECB,CBC): ")
            plaintext = input("Text: ").encode()
            if (choice == "ECB"):
                print(str(base64.b64encode(encryptAESText(plaintext, key))))
            elif (choice == "CBC"):
                print(str(base64.b64encode(encryptAESText(plaintext, key, "CBC"))))
        elif (choice == "F"):
            choice = input("Mode(ECB,CBC): ")
            filename = input("Filename: ")
            if (choice == "ECB"):
                encryptAESFile(filename, key)
            elif (choice == "CBC"):
                encryptAESFile(filename, key, "CBC")
        print('Done.')
    elif choice == 'D':
        choice = input("Text(T) or File(F) to Decrypt: ")
        key = input("Key: ").encode()
        if (choice == "T"):
            choice = input("Mode(ECB,CBC): ")
            ciphertext = input("Text: ").encode()
            ciphertext = base64.b64decode(ciphertext)
            if (choice == "ECB"):
                print(str(decryptAESText(ciphertext, key)))
            elif (choice == "CBC"):
                print(str(decryptAESText(ciphertext, key, "CBC")))
        elif (choice == "F"):
            choice = input("Mode(ECB,CBC): ")
            filename = input("Filename: ")
            if (choice == "ECB"):
                decryptAESFile(filename, key)
            elif (choice == "CBC"):
                decryptAESFile(filename, key, "CBC")
        print('Done.')
    else:
        print("No option selected, closing...")


main()