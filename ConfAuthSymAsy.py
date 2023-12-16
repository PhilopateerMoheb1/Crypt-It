from RSA import *
from SHA512 import *
from Cryptography import *



# signedFileHash=""

def ConfAuthHashSignedAES(file_path,symKey,mode="ECB",IV=b"0000000000000000"):
    # Read the content of the file
    with open(file_path, "rb") as file:
        file_content = file.read()

    # Calculate the hash of the file content
    file_hash = hash_file(file_path)
    print(file_hash)
    with open("private.pem", "rb") as f:
        private_key = rsa.PrivateKey.load_pkcs1(f.read())

    signedFileHash=sign_messageRSA(file_hash,private_key)
    
    # Concatenate file content and hash
    concatenated_data = file_content + b"\nEncrypted Hash:" + signedFileHash

    # Write the concatenated data to a new file
    with open("(Conc)"+file_path, "wb") as output_file:
        output_file.write(concatenated_data)
    if(mode=="ECB"):
        encryptAESFile("(Conc)"+file_path,symKey,mode)
    elif(mode=="CBC"):
        encryptAESFile("(Conc)"+file_path,symKey,mode,IV)


def ConfAuthHashVerifyAES(file_path,symKey,mode="ECB",IV=b"0000000000000000"):
    if(mode=="ECB"):
        decryptAESFile("(enc)(Conc)"+file_path,symKey,mode)
    elif(mode=="CBC"):
        decryptAESFile("(enc)(Conc)"+file_path,symKey,mode,IV)
    # Read the concatenated data from the file
    with open("(dec)(Conc)"+file_path, "rb") as file:
        concatenated_data = file.read()
    # Split the data into file content and hash
    file_content, hash_separator, fileHashSignedEncrypted = concatenated_data.rpartition(b"\nEncrypted Hash:")
    with open(file_path, "wb") as output_file:
        output_file.write(file_content)
    
    with open("public.pem", "rb") as f:
        public_key = rsa.PublicKey.load_pkcs1(f.read())
    # Convert the hash string to bytes
    # file_hash = fileHashSignedEncrypted.decode("utf-8")
    # Verify the file integrity by recalculating the hash
    calculated_hash = hash_file(file_path)
    print(calculated_hash)
    
    
    FileHash= verify_messageRSA(calculated_hash,fileHashSignedEncrypted,public_key)
    print(FileHash)
    # Compare the calculated hash with the extracted hash
    if FileHash:
        print("File integrity verified.")
    else:
        print("File has been altered.")

def main():
    ConfAuthHashSignedAES("Test.txt",b"PhiloPteer Mohebmmmmmmmmmmmmmmmm","ECB")
    ConfAuthHashVerifyAES("Test.txt",b"PhiloPteer Mohebmmmmmmmmmmmmmmmm","ECB")
    
    
main()