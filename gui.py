import base64
from tkinter import *
from tkinter import filedialog
from Cryptography import *

root = Tk()

root.title('Crypt-It')

# options frame and its constituents
options_frame = LabelFrame(root, text="Choose your options:", padx=20, pady=56)
options_frame.grid(row=0, column=0)

options = ["AES (ECB)", "AES (CBC)", "RSA", "sha512"]

clicked = StringVar()
clicked.set("Choose Tool")


# show appropriate buttons when an option is selected
def on_selection(*args):
    if selected.get() == "AES (ECB)":
        key_field.grid(row=1, column=0, columnspan=10, pady=10)
        en_button.grid(row=7, column=0, padx=4)
        dec_button.grid(row=7, column=2, padx=4)
    elif selected.get() == "AES (CBC)":
        key_field.grid(row=1, column=0, columnspan=10, pady=10)
        en_button.grid(row=7, column=0, padx=4)
        dec_button.grid(row=7, column=2, padx=4)
        iv_field.grid(row=2, column=0, columnspan=10, pady=10)


selected = StringVar(root)
selected.set("Choose Tool")

drop = OptionMenu(options_frame, selected, *options, command=on_selection)
drop.config(width=60)
drop.grid(row=0, column=0, columnspan=10)

key_field = Text(options_frame, width=50, height=15)
key_field.insert(END, "Enter Your Key")
key_field.grid(row=1, column=0, columnspan=10, pady=10)
key_field.grid_forget()

iv_field = Text(options_frame, width=50, height=1)
iv_field.insert(END, "Enter Your Initialization Vector")
iv_field.grid(row=2, column=0, columnspan=10, pady=10)
iv_field.grid_forget()


def en_aes():
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
        output_text.config(state="normal")
        output_text.delete("1.0", END)
        output_text.insert(END, "done")
        output_text.config(state="disabled")
    elif (selected.get() == "AES (CBC)") & file_opened:
        filename = os.path.basename(filepath)
        key = key_field.get("1.0", END).replace("\n", "")
        iv = iv_field.get("1.0", END).replace("\n", "")
        encryptAESFile(filename, key.encode(), "CBC", iv.encode())
        output_text.config(state="normal")
        output_text.delete("1.0", END)
        output_text.insert(END, "done")
        output_text.config(state="disabled")


def dec_aes():
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
        output_text.config(state="normal")
        output_text.delete("1.0", END)
        output_text.insert(END, "done")
        output_text.config(state="disabled")
    elif (selected.get() == "AES (CBC)") & file_opened:
        filename = os.path.basename(filepath)
        key = key_field.get("1.0", END).replace("\n", "")
        iv = iv_field.get("1.0", END).replace("\n", "")
        decryptAESFile(filename, key.encode(), "CBC", iv.encode())
        output_text.config(state="normal")
        output_text.delete("1.0", END)
        output_text.insert(END, "done")
        output_text.config(state="disabled")


en_button = Button(options_frame, text="ENCRYPT", pady=10, padx=20, width=22, command=en_aes)
en_button.grid(row=7, column=0, padx=4)
en_button.grid_forget()

dec_button = Button(options_frame, text="DECRYPT", pady=10, padx=20, width=22, command=dec_aes)
dec_button.grid(row=7, column=2, padx=4)
dec_button.grid_forget()

# right frame
r_frame = LabelFrame(root, borderwidth=0, highlightthickness=0)
r_frame.grid(row=0, column=1)

# input frame and its constituents
in_frame = LabelFrame(r_frame, text="INPUT TEXT", padx=10, pady=10)
in_frame.pack(pady=10)

input_text = Text(in_frame, width=50, height=10)
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
file_button = Button(in_frame, text="Open File", command=open_file, width=57)
file_button.grid(row=1, column=0)

# output frame and its constituents
out_frame = LabelFrame(r_frame, text="OUTPUT TEXT", padx=10, pady=10)
out_frame.pack(pady=10)

output_text = Text(out_frame, width=50, height=10)
output_text.insert(END, "Result")
output_text.config(state="disabled")
output_text.grid(row=0, column=0, pady=5)

root.mainloop()
