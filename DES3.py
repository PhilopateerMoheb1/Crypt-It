import os
from Crypto.Cipher import DES3
from hashlib import md5


def encrypt_file_des3(file_path, key):
    key_hash = md5(key.encode('ascii')).digest()
    tdes_key = DES3.adjust_key_parity(key_hash)
    cipher = DES3.new(tdes_key, DES3.MODE_EAX, nonce=b'0')

    with open(file_path, "rb") as input_file:
        encrypted_file = cipher.encrypt(input_file.read())

    filename = os.path.basename(file_path)

    with open("encodedDES3_" + filename, "wb") as output_file:
        output_file.write(encrypted_file)


def encrypt_text_des3(plaintext, key):
    key_hash = md5(key.encode('ascii')).digest()
    tdes_key = DES3.adjust_key_parity(key_hash)
    cipher = DES3.new(tdes_key, DES3.MODE_EAX, nonce=b'0')

    ciphertext = cipher.encrypt(plaintext.encode())

    return ciphertext


def decrypt_file_des3(file_path, key):
    key_hash = md5(key.encode('ascii')).digest()
    tdes_key = DES3.adjust_key_parity(key_hash)
    cipher = DES3.new(tdes_key, DES3.MODE_EAX, nonce=b'0')

    with open(file_path, "rb") as input_file:
        decrypted_file = cipher.decrypt(input_file.read())

    filename = os.path.basename(file_path)

    with open("decodedDES3_" + filename, "wb") as output_file:
        output_file.write(decrypted_file)


def decrypt_text_des3(ciphertext, key):
    key_hash = md5(key.encode('ascii')).digest()
    tdes_key = DES3.adjust_key_parity(key_hash)
    cipher = DES3.new(tdes_key, DES3.MODE_EAX, nonce=b'0')

    plaintext = cipher.decrypt(ciphertext)

    return plaintext
