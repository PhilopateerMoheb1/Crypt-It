import base64
import rsa;


def generate_keys(mode="F"):
    #F : Fast S:Secure (fast it will be 2048 Secure it will be 4096)
    if(mode==F):
        public_key, private_key = rsa.newkeys(2048)
    elif(mode=="S"):
        public_key, private_key = rsa.newkeys(4096)
    with open("public.pem", "wb") as f:
        f.write(public_key.save_pkcs1("PEM"))

    with open("private.pem", "wb") as f:
        f.write(private_key.save_pkcs1("PEM"))

def encrypt_messageRSA(message, public_key):
    encrypted_message = rsa.encrypt(message.encode(), public_key)
    with open("encrypted.message", "wb") as f:
        f.write(encrypted_message)
    return encrypted_message

def encrypt_fileRSA(file_name, public_key):
    with open(file_name, 'rb') as f:
        file_content = f.read()
        encrypted_content = rsa.encrypt(file_content, public_key)
    with open("encrypted_" + file_name, 'wb') as f:
        f.write(encrypted_content)

def decrypt_messageRSA(encrypted_message, private_key):
    clear_message = rsa.decrypt(encrypted_message, private_key)
    return clear_message.decode()

def decrypt_fileRSA(file_name, private_key):
    with open(file_name, 'rb') as f:
        encrypted_content = f.read()
        decrypted_content = rsa.decrypt(encrypted_content, private_key)
    with open("decrypted_" + file_name, 'wb') as f:
        f.write(decrypted_content)

def sign_messageRSA(message, private_key):
    signature = rsa.sign(message.encode(), private_key, "SHA-256")
    with open("signature", "wb") as f:
        f.write(signature)
    return signature

def sign_fileRSA(file_name, private_key):
    with open(file_name, 'rb') as f:
        file_content = f.read()
        signature = rsa.sign(file_content, private_key, 'SHA-256')
    with open("signature_" + file_name, 'wb') as f:
        f.write(signature)

def verify_messageRSA(message, signature, public_key):
    try:
        return rsa.verify(message.encode(), signature, public_key)
    except:
        return 0
def verify_fileRSA(file_name, public_key):
    with open(file_name, 'rb') as f:
        file_content = f.read()
    with open("signature_" + file_name, 'rb') as f:
        signature = f.read()
    verified = rsa.verify(file_content, signature, public_key)
    if verified:
        print("Signature verified: File has not been tampered with.")
    else:
        print("Verification failed: File has been tampered with.")


def main():
    generate_keys()
    while(1):
        with open("public.pem", "rb") as f:
            public_key = rsa.PublicKey.load_pkcs1(f.read())

        with open("private.pem", "rb") as f:
            private_key = rsa.PrivateKey.load_pkcs1(f.read())

        choice = input("Would you like to (E)encrypt or (D)Decrypt or (S)Signature or (V)Verification \n")
        if choice == 'E':
            choice = input("Text(T) or File(F) to encrypt: ")
            if(choice=="T"):
                message = input("Enter message to encrypt: ")
                encrypted_msg = str(base64.b64encode(encrypt_messageRSA(message, public_key)))
                print(f"Encrypted message: {encrypted_msg}")
            elif(choice=="F"):
                file_name = input("Enter file name to encrypt: ")
                encrypt_fileRSA(file_name, public_key)
                print("File encrypted successfully.")
        elif choice == 'D':
            choice = input("Text(T) or File(F) to decrypt: ")
            if(choice=="T"):
                encrypted_msg = input("Enter message to decrypt: ")
                encrypted_msg=base64.b64decode(encrypted_msg)
                decrypted_msg = decrypt_messageRSA(encrypted_msg, private_key)
                print(f"Decrypted message: {decrypted_msg}")
            elif(choice=="F"):
                file_name = input("Enter file name to decrypt: ")
                decrypt_fileRSA(file_name, private_key)
                print("File decrypted successfully.")
        elif choice == 'S':
            choice = input("Text(T) or File(F) to sign: ")
            if(choice=="T"):
                message = input("Enter message to sign: ")
                signature = sign_messageRSA(message, private_key)
                print(f"Signature: {signature}")
            elif(choice=="F"):
                file_name = input("Enter file name to sign: ")
                sign_fileRSA(file_name, private_key)
                print("File signed successfully.")
        elif choice == 'V':
            choice = input("Text(T) or File(F) to sign: ")
            if(choice=="T"):
                signature = input("Enter signed message to verify: ")
                verified = verify_messageRSA(message, signature, public_key)
                if verified:
                    print("Signature verified: Message has not been tampered with.")
                else:
                    print("Verification failed: Message has been tampered with.")
            elif(choice=="F"):
                file_name = input("Enter file name to verify signature: ")
                verified = verify_fileRSA(file_name, public_key)
        else:
            print("No option selected, closing...")

if __name__ == "__main__":
    main()
