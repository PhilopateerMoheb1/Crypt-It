from tkinter import *

root = Tk()

root.title('Crypt-It')

# options frame and its constituents
options_frame = LabelFrame(root, text="Choose your options:", padx=20, pady=50)
options_frame.grid(row=0, column=0)

options = ["AES", "RSA", "sha512"]

clicked = StringVar()
clicked.set("Choose Tool")


# show appropriate buttons when an option is selected
def on_selection(*args):
    if selected.get() == "AES":
        key_field.grid(row=1, column=0, columnspan=10, pady=10)
        en_button.grid(row=7, column=0, padx=4)
        dec_button.grid(row=7, column=2, padx=4)


selected = StringVar(root)
selected.set("Choose Tool")

drop = OptionMenu(options_frame, selected, *options, command=on_selection)
drop.config(width=60)
drop.grid(row=0, column=0, columnspan=10)

key_field = Text(options_frame, width=50, height=15)
key_field.insert(END, "Enter Your Key")
key_field.grid(row=1, column=0, columnspan=10, pady=10)
key_field.grid_forget()

en_button = Button(options_frame, text="ENCRYPT", pady=10, padx=20, width=22)
en_button.grid(row=7, column=0, padx=4)
en_button.grid_forget()

dec_button = Button(options_frame, text="DECRYPT", pady=10, padx=20, width=22)
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

# output frame and its constituents
out_frame = LabelFrame(r_frame, text="OUTPUT TEXT", padx=10, pady=10)
out_frame.pack(pady=10)

output_text = Text(out_frame, width=50, height=10)
output_text.insert(END, "Result")
output_text.config(state="disabled")
output_text.grid(row=0, column=0, pady=5)

root.mainloop()
