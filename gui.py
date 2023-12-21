import base64
from tkinter import *
from tkinter import filedialog
from Cryptography import *
from RSA import *
from SHA512 import *
from DES3 import *

root = Tk()

root.title('Crypt-It')
root.config(bg="#e09f3e")

# options frame and its constituents
options_frame = LabelFrame(root, text="Choose your options:", padx=20, pady=56, bg="#e09f3e")
options_frame.grid(row=0, column=0)

options = ["AES (ECB)", "AES (CBC)", "RSA", "sha512", "Triple DES"]

clicked = StringVar()
clicked.set("Choose Tool")

public_key = StringVar()
private_key = StringVar()


# show appropriate buttons when an option is selected
def on_selection(*args):
    if selected.get() == "AES (ECB)":
        key_field.grid(row=1, column=0, columnspan=10, pady=10)
        aes_en_button.grid(row=7, column=0, padx=4)
        aes_dec_button.grid(row=7, column=2, padx=4)
        iv_field.grid_forget()
        rsa_enc_button.grid_forget()
        rsa_dec_button.grid_forget()
        rsa_sign_button.grid_forget()
        rsa_verify_button.grid_forget()
        des_en_button.grid_forget()
        des_dec_button.grid_forget()
    elif selected.get() == "AES (CBC)":
        key_field.grid(row=1, column=0, columnspan=10, pady=10)
        aes_en_button.grid(row=7, column=0, padx=4)
        aes_dec_button.grid(row=7, column=2, padx=4)
        iv_field.grid(row=2, column=0, columnspan=10, pady=10)
        rsa_enc_button.grid_forget()
        rsa_dec_button.grid_forget()
        rsa_sign_button.grid_forget()
        rsa_verify_button.grid_forget()
        des_en_button.grid_forget()
        des_dec_button.grid_forget()
    elif selected.get() == "RSA":
        global public_key
        global private_key
        aes_en_button.grid_forget()
        aes_dec_button.grid_forget()
        iv_field.grid_forget()
        key_field.grid_forget()
        des_en_button.grid_forget()
        des_dec_button.grid_forget()
        rsa_enc_button.grid(row=1, column=0, padx=4, pady=5)
        rsa_dec_button.grid(row=1, column=1, padx=4, pady=5)
        rsa_sign_button.grid(row=2, column=0, padx=4, pady=5)
        rsa_verify_button.grid(row=2, column=1, padx=4, pady=5)
        generate_keys()
        with open("public.pem", "rb") as f:
            public_key = rsa.PublicKey.load_pkcs1(f.read())

        with open("private.pem", "rb") as f:
            private_key = rsa.PrivateKey.load_pkcs1(f.read())
    elif selected.get() == "sha512":
        hash_button.grid(row=1, column=0, padx=4, pady=5)
        key_field.grid_forget()
        aes_en_button.grid_forget()
        aes_dec_button.grid_forget()
        iv_field.grid_forget()
        rsa_enc_button.grid_forget()
        rsa_dec_button.grid_forget()
        rsa_sign_button.grid_forget()
        rsa_verify_button.grid_forget()
        des_en_button.grid_forget()
        des_dec_button.grid_forget()
    elif selected.get() == "Triple DES":
        key_field.grid(row=1, column=0, columnspan=10, pady=10)
        des_en_button.grid(row=7, column=0, padx=4)
        des_dec_button.grid(row=7, column=2, padx=4)
        iv_field.grid_forget()
        aes_en_button.grid_forget()
        aes_dec_button.grid_forget()
        rsa_enc_button.grid_forget()
        rsa_dec_button.grid_forget()
        rsa_sign_button.grid_forget()
        rsa_verify_button.grid_forget()


selected = StringVar(root)
selected.set("Choose Tool")

drop = OptionMenu(options_frame, selected, *options, command=on_selection)
drop.config(width=60, bg="#003049", fg="#e9c46a")
drop.grid(row=0, column=0, columnspan=10)

key_field = Text(options_frame, width=50, height=15, bg="#FDF0D5")
key_field.insert(END, "Enter Your Key")
key_field.grid(row=1, column=0, columnspan=10, pady=10)
key_field.grid_forget()

iv_field = Text(options_frame, width=50, height=1, bg="#FDF0D5")
iv_field.insert(END, "Enter Your Initialization Vector")
iv_field.grid(row=2, column=0, columnspan=10, pady=10)
iv_field.grid_forget()


def find_file_recursive(file_name):
    for root, dirs, files in os.walk(os.getcwd()):
        if file_name in files:
            return os.path.join(root, file_name)
    return None


# aes functions
def en_aes():
    global file_opened
    if (selected.get() == "AES (ECB)") & (not file_opened):
        plaintext = input_text.get("1.0", END).replace("\n", "")
        key = key_field.get("1.0", END).replace("\n", "")
        ciphertext = str(base64.b64encode(encryptAESText(plaintext.encode(), key.encode())))
        ciphertext = ciphertext.replace("b'", "").replace("'", "")
        output_text.config(state="normal")
        output_text.delete("1.0", END)
        output_text.insert(END, ciphertext)
        output_text.config(state="disabled")
    elif (selected.get() == "AES (CBC)") & (not file_opened):
        plaintext = input_text.get("1.0", END).replace("\n", "")
        key = key_field.get("1.0", END).replace("\n", "")
        iv = iv_field.get("1.0", END).replace("\n", "")
        ciphertext = str(base64.b64encode(encryptAESText(plaintext.encode(), key.encode(), "CBC", iv.encode())))
        ciphertext = ciphertext.replace("b'", "").replace("'", "")
        output_text.config(state="normal")
        output_text.delete("1.0", END)
        output_text.insert(END, ciphertext)
        output_text.config(state="disabled")
    elif (selected.get() == "AES (ECB)") & file_opened:
        filename = os.path.basename(filepath)
        key = key_field.get("1.0", END).replace("\n", "")
        encryptAESFile(filename, key.encode())
        out_filepath = find_file_recursive("(enc)" + filename)
        output_text.config(state="normal")
        output_text.delete("1.0", END)
        output_text.insert(END, "Done - Filepath: " + out_filepath)
        output_text.config(state="disabled")
        file_opened = False
    elif (selected.get() == "AES (CBC)") & file_opened:
        filename = os.path.basename(filepath)
        key = key_field.get("1.0", END).replace("\n", "")
        iv = iv_field.get("1.0", END).replace("\n", "")
        encryptAESFile(filename, key.encode(), "CBC", iv.encode())
        out_filepath = find_file_recursive("(enc)" + filename)
        output_text.config(state="normal")
        output_text.delete("1.0", END)
        output_text.insert(END, "Done - Filepath: " + out_filepath)
        output_text.config(state="disabled")
        file_opened = False


def dec_aes():
    global file_opened
    if (selected.get() == "AES (ECB)") & (not file_opened):
        ciphertext = base64.b64decode(input_text.get("1.0", END).replace("\n", ""))
        key = key_field.get("1.0", END).replace("\n", "")
        plaintext = decryptAESText(ciphertext, key.encode())
        output_text.config(state="normal")
        output_text.delete("1.0", END)
        output_text.insert(END, plaintext)
        output_text.config(state="disabled")
    elif (selected.get() == "AES (CBC)") & (not file_opened):
        ciphertext = base64.b64decode(input_text.get("1.0", END).replace("\n", ""))
        key = key_field.get("1.0", END).replace("\n", "")
        iv = iv_field.get("1.0", END).replace("\n", "")
        plaintext = decryptAESText(ciphertext, key.encode(), "CBC", iv.encode())
        output_text.config(state="normal")
        output_text.delete("1.0", END)
        output_text.insert(END, plaintext)
        output_text.config(state="disabled")
    elif (selected.get() == "AES (ECB)") & file_opened:
        filename = os.path.basename(filepath)
        key = key_field.get("1.0", END).replace("\n", "")
        decryptAESFile(filename, key.encode())
        out_filepath = find_file_recursive("(dec)" + filename)
        output_text.config(state="normal")
        output_text.delete("1.0", END)
        output_text.insert(END, "Done - Filepath: " + out_filepath)
        output_text.config(state="disabled")
        file_opened = False
    elif (selected.get() == "AES (CBC)") & file_opened:
        filename = os.path.basename(filepath)
        key = key_field.get("1.0", END).replace("\n", "")
        iv = iv_field.get("1.0", END).replace("\n", "")
        decryptAESFile(filename, key.encode(), "CBC", iv.encode())
        out_filepath = find_file_recursive("(dec)" + filename.replace("(enc)", ""))
        output_text.config(state="normal")
        output_text.delete("1.0", END)
        output_text.insert(END, "Done - Filepath: " + out_filepath)
        output_text.config(state="disabled")
        file_opened = False


# AES Buttons
aes_en_button = Button(options_frame, text="ENCRYPT", pady=10, padx=20, width=22, command=en_aes, bg="#780000",
                       fg="#e9c46a")
aes_en_button.grid(row=7, column=0, padx=4)
aes_en_button.grid_forget()

aes_dec_button = Button(options_frame, text="DECRYPT", pady=10, padx=20, width=22, command=dec_aes, bg="#780000",
                        fg="#e9c46a")
aes_dec_button.grid(row=7, column=2, padx=4)
aes_dec_button.grid_forget()

temp_input = None


# rsa functions
def enc_rsa():
    global file_opened
    global private_key
    global public_key
    global temp_input
    if (selected.get() == "RSA") & file_opened:
        filename = os.path.basename(filepath)
        encrypt_fileRSA(filename, public_key)
        out_filepath = find_file_recursive("encrypted_" + filename)
        output_text.config(state="normal")
        output_text.delete("1.0", END)
        output_text.insert(END, "Done - Filepath: " + out_filepath)
        output_text.config(state="disabled")
        file_opened = False
    elif (selected.get() == "RSA") & (not file_opened):
        plaintext = input_text.get("1.0", END).replace("\n", "")
        ciphertext = str(base64.b64encode(encrypt_messageRSA(plaintext, public_key)))
        ciphertext = ciphertext.replace("b'", "").replace("'", "")
        output_text.config(state="normal")
        output_text.delete("1.0", END)
        output_text.insert(END, ciphertext)
        output_text.config(state="disabled")



def dec_rsa():
    global file_opened
    global private_key
    global public_key
    global temp_input
    if (selected.get() == "RSA") & file_opened:
        filename = os.path.basename(filepath)
        decrypt_fileRSA(filename, private_key)
        out_filepath = find_file_recursive("decrypted_" + filename)
        output_text.config(state="normal")
        output_text.delete("1.0", END)
        output_text.insert(END, "Done - Filepath: " + out_filepath)
        output_text.config(state="disabled")
        file_opened = False
    elif (selected.get() == "RSA") & (not file_opened):
        ciphertext = base64.b64decode(input_text.get("1.0", END).replace("\n", ""))
        plaintext = decrypt_messageRSA(ciphertext, private_key)
        output_text.config(state="normal")
        output_text.delete("1.0", END)
        output_text.insert(END, plaintext)
        output_text.config(state="disabled")
        input_text.config(state="normal")


def sign_rsa():
    global file_opened
    global private_key
    global public_key
    if (selected.get() == "RSA") & file_opened:
        filename = os.path.basename(filepath)
        sign_fileRSA(filename, private_key)
        out_filepath = find_file_recursive("signature_" + filename)
        output_text.config(state="normal")
        output_text.delete("1.0", END)
        output_text.insert(END, "Done - Filepath: " + out_filepath)
        output_text.config(state="disabled")
        file_opened = False
    elif (selected.get() == "RSA") & (not file_opened):
        message = input_text.get("1.0", END).replace("\n", "")
        sign_messageRSA(message, private_key)
        out_filepath = find_file_recursive("signature_msg.txt")
        output_text.config(state="normal")
        output_text.delete("1.0", END)
        output_text.insert(END, "Done - Filepath: " + out_filepath)
        output_text.config(state="disabled")


def verify_rsa():
    global file_opened
    global private_key
    global public_key
    if (selected.get() == "RSA") & file_opened:
        filename = os.path.basename(filepath)
        result = verify_fileRSA(filename, public_key)
        output_text.config(state="normal")
        output_text.delete("1.0", END)
        output_text.insert(END, result)
        output_text.config(state="disabled")
        file_opened = False
    elif (selected.get() == "RSA") & (not file_opened):
        message = input_text.get("1.0", END).replace("\n", "")
        verified = verify_messageRSA(message, public_key)
        if verified:
            result = "Signature verified: Message has not been tampered with."
        else:
            result = "Verification failed: Message has been tampered with."
        output_text.config(state="normal")
        output_text.delete("1.0", END)
        output_text.insert(END, result)
        output_text.config(state="disabled")
        input_text.config(state="normal")


# RSA Buttons
rsa_enc_button = Button(options_frame, text="ENCRYPT", pady=10, padx=20, width=22, command=enc_rsa, bg="#780000",
                        fg="#e9c46a")
rsa_enc_button.grid(row=1, column=0, padx=4, pady=5)
rsa_enc_button.grid_forget()

rsa_dec_button = Button(options_frame, text="DECRYPT", pady=10, padx=20, width=22, command=dec_rsa, bg="#780000",
                        fg="#e9c46a")
rsa_dec_button.grid(row=1, column=1, padx=4, pady=5)
rsa_dec_button.grid_forget()

rsa_sign_button = Button(options_frame, text="SIGN", pady=10, padx=20, width=22, command=sign_rsa, bg="#780000",
                         fg="#e9c46a")
rsa_sign_button.grid(row=2, column=0, padx=4, pady=5)
rsa_sign_button.grid_forget()

rsa_verify_button = Button(options_frame, text="VERIFY", pady=10, padx=20, width=22, command=verify_rsa, bg="#780000",
                           fg="#e9c46a")
rsa_verify_button.grid(row=2, column=1, padx=4, pady=5)
rsa_verify_button.grid_forget()


# hush functions
def hash_function():
    global file_opened
    if (selected.get() == "sha512") & file_opened:
        result = hash_file(filepath)
        output_text.config(state="normal")
        output_text.delete("1.0", END)
        output_text.insert(END, result)
        output_text.config(state="disabled")
        file_opened = False
    elif (selected.get() == "sha512") & (not file_opened):
        text = input_text.get("1.0", END).replace("\n", "")
        result = hash_text(text)
        output_text.config(state="normal")
        output_text.delete("1.0", END)
        output_text.insert(END, result)
        output_text.config(state="disabled")


# sha512 hash buttons
hash_button = Button(options_frame, text="HASH", pady=10, padx=20, width=50, command=hash_function, bg="#780000",
                     fg="#e9c46a")
hash_button.grid(row=1, column=0, padx=4, pady=5)
hash_button.grid_forget()

encoded_message = None


# DES3 functions
def enc_des3():
    global encoded_message
    global file_opened
    if (selected.get() == "Triple DES") & file_opened:
        filename = os.path.basename(filepath)
        key = key_field.get("1.0", END).replace("\n", "")
        encrypt_file_des3(filepath, key)
        out_filepath = find_file_recursive("encodedDES3_" + filename)
        output_text.config(state="normal")
        output_text.delete("1.0", END)
        output_text.insert(END, "Done - Filepath: " + out_filepath)
        output_text.config(state="disabled")
        file_opened = False
    elif (selected.get() == "Triple DES") & (not file_opened):
        plaintext = input_text.get("1.0", END).replace("\n", "")
        key = key_field.get("1.0", END).replace("\n", "")
        ciphertext = str(base64.b64encode(encrypt_text_des3(plaintext, key)))
        ciphertext = ciphertext.replace("b'", "").replace("'", "")
        output_text.config(state="normal")
        output_text.delete("1.0", END)
        output_text.insert(END, ciphertext)
        output_text.config(state="disabled")



def dec_des3():
    global file_opened
    global encoded_message
    if (selected.get() == "Triple DES") & file_opened:
        filename = os.path.basename(filepath)
        key = key_field.get("1.0", END).replace("\n", "")
        decrypt_file_des3(filepath, key)
        out_filepath = find_file_recursive("decodedDES3_" + filename)
        output_text.config(state="normal")
        output_text.delete("1.0", END)
        output_text.insert(END, "Done - Filepath: " + out_filepath)
        output_text.config(state="disabled")
        file_opened = False
    elif (selected.get() == "Triple DES") & (not file_opened):
        ciphertext = base64.b64decode(input_text.get("1.0", END).replace("\n", ""))
        key = key_field.get("1.0", END).replace("\n", "")
        plaintext = decrypt_text_des3(ciphertext, key)
        output_text.config(state="normal")
        output_text.delete("1.0", END)
        output_text.insert(END, plaintext)
        output_text.config(state="disabled")


# DES3 buttons
des_en_button = Button(options_frame, text="ENCRYPT", pady=10, padx=20, width=22, command=enc_des3, bg="#780000",
                       fg="#e9c46a")
des_en_button.grid(row=7, column=0, padx=4)
des_en_button.grid_forget()

des_dec_button = Button(options_frame, text="DECRYPT", pady=10, padx=20, width=22, command=dec_des3, bg="#780000",
                        fg="#e9c46a")
des_dec_button.grid(row=7, column=2, padx=4)
des_dec_button.grid_forget()

# right frame
r_frame = LabelFrame(root, borderwidth=0, highlightthickness=0, bg="#e09f3e")
r_frame.grid(row=0, column=1)

# input frame and its constituents
in_frame = LabelFrame(r_frame, text="INPUT TEXT", padx=10, pady=10, bg="#e09f3e")
in_frame.pack(pady=10)

input_text = Text(in_frame, width=50, height=10, bg="#FDF0D5")
input_text.insert(END, "Enter Text")
input_text.grid(row=0, column=0, pady=5)

filepath = StringVar


def open_file():
    global filepath
    filepath = filedialog.askopenfilename(title="Select A File", filetypes=(("text files", "*.txt"),))
    if filepath:
        global file_opened
        file_opened = True
        with open(filepath, 'r') as file:
            file_content = file.read()
            input_text.delete("1.0", END)
            input_text.insert(END, file_content)


file_opened = False
file_button = Button(in_frame, text="Open File", command=open_file, width=57, bg="#780000", fg="#e9c46a")
file_button.grid(row=1, column=0)

# output frame and its constituents
out_frame = LabelFrame(r_frame, text="OUTPUT TEXT", padx=10, pady=10, bg="#e09f3e")
out_frame.pack(pady=10)

output_text = Text(out_frame, width=50, height=10, bg="#FDF0D5")
output_text.insert(END, "Result")
output_text.config(state="disabled")
output_text.grid(row=0, column=0, pady=5)

root.mainloop()
