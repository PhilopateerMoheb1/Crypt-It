import hashlib


def hash_text(text, algorithm="sha256"):
    # Choose the hash algorithm (default is SHA-256)
    hash_function = hashlib.new(algorithm)

    # Encode the text as bytes and update the hash function
    hash_function.update(text.encode("utf-8"))

    # Get the hexadecimal representation of the hash
    text_hash = hash_function.hexdigest()

    return text_hash

def hash_file(file_path, algorithm="sha256", buffer_size=8192):
    hash_function = hashlib.new(algorithm)

    with open(file_path, "rb") as file:
        while chunk := file.read(buffer_size):
            hash_function.update(chunk)

    return hash_function.hexdigest()

def main():
    choice = input("Choose between File 'F' or Text 'T': ")
    if(choice=="T"):
            text_input = input("Enter the text to hash: ")
            print(hash_text(text_input))

    elif(choice=="F"):
        file_path = input("Enter the file path: ")
        print(hash_file(file_path))
        
print('Done.')
    
if __name__ == "__main__":
    main()

