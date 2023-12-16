from cryptography.hazmat.primitives import hashes

def sha512_hash(data):
    hash_object = hashes.Hash(hashes.SHA512())
    hash_object.update(data)
    digest = hash_object.finalize()
    return digest.hex()

def get_file_hash(file_path):
    try:
        with open(file_path, 'rb') as file:
            file_data = file.read()
            file_hash = sha512_hash(file_data)
            print(f"SHA-512 Hash of the file '{file_path}': {file_hash}")

    except FileNotFoundError:
        print("File not found.")

def get_text_hash(text_input):
    text_hash = sha512_hash(text_input)
    print(f"SHA-512 Hash of the text: {text_hash}")

def main():
    choice = input("Choose between File 'F' or Text 'T': ")
    if(choice=="T"):
            text_input = input("Enter the text to hash: ").encode()
            get_text_hash(text_input)

    elif(choice=="F"):
        file_path = input("Enter the file path: ")
        get_file_hash(file_path)
        
print('Done.')
    
if __name__ == "__main__":
    main()

