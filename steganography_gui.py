import cv2
import numpy as np
import os
from tkinter import Tk, Label, Button, filedialog, Entry, Text, messagebox
from PIL import Image, ImageTk
from cryptography.fernet import Fernet

# Generate encryption key if not exists
def generate_key():
    if not os.path.exists("secret.key"):
        key = Fernet.generate_key()
        with open("secret.key", "wb") as key_file:
            key_file.write(key)

# Load encryption key
def load_key():
    return open("secret.key", "rb").read()

# Encrypt message
def encrypt_message(message, key):
    fernet = Fernet(key)
    return fernet.encrypt(message.encode())

# Decrypt message
def decrypt_message(encrypted_message, key):
    fernet = Fernet(key)
    return fernet.decrypt(encrypted_message).decode()

# Convert data to binary
def data_to_binary(data):
    return ''.join(format(ord(i), '08b') for i in data)

# Hide data in an image (LSB Steganography)
def hide_data(image_path, secret_data, output_path):
    image = cv2.imread(image_path)
    if image is None:
        messagebox.showerror("Error", "Invalid image format. Use PNG or JPG.")
        return

    secret_data += "#####"  # Delimiter to mark the end
    binary_secret_data = data_to_binary(secret_data)
    
    data_index = 0
    for i in range(image.shape[0]):
        for j in range(image.shape[1]):
            for k in range(image.shape[2]):  # RGB channels
                if data_index < len(binary_secret_data):
                    pixel = list(image[i, j])
                    pixel[k] = int(format(pixel[k], '08b')[:-1] + binary_secret_data[data_index], 2)
                    image[i, j] = tuple(pixel)
                    data_index += 1

    cv2.imwrite(output_path, image)
    messagebox.showinfo("Success", f"Data hidden in {output_path}")

# Extract data from image
def extract_data(image_path, key):
    image = cv2.imread(image_path)
    if image is None:
        messagebox.showerror("Error", "Invalid image format.")
        return ""

    binary_data = ""
    for i in range(image.shape[0]):
        for j in range(image.shape[1]):
            for k in range(image.shape[2]):
                binary_data += format(image[i, j, k], '08b')[-1]

    all_bytes = [binary_data[i:i+8] for i in range(0, len(binary_data), 8)]
    secret_data = "".join(chr(int(byte, 2)) for byte in all_bytes)

    if "#####" in secret_data:
        secret_data = secret_data[:secret_data.index("#####")]
        try:
            decrypted_message = decrypt_message(secret_data.encode('latin-1'), key)
            return decrypted_message
        except Exception as e:
            return f"Decryption failed: {e}"
    else:
        return "No hidden message found."

# GUI Application
class SteganographyApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Image Steganography")
        self.root.geometry("500x500")
        
        Label(root, text="Steganography Tool", font=("Arial", 16, "bold")).pack(pady=10)

        # Select Image
        self.image_label = Label(root, text="No Image Selected", fg="red")
        self.image_label.pack()
        Button(root, text="Select Image", command=self.load_image).pack(pady=5)

        # Secret Message Input
        Label(root, text="Enter Secret Message:").pack()
        self.message_entry = Entry(root, width=50)
        self.message_entry.pack()

        # Hide Data Button
        Button(root, text="Hide Message", command=self.hide_message).pack(pady=5)

        # Extract Message Button
        Button(root, text="Extract Message", command=self.extract_message).pack(pady=5)

        # Output Text Box
        Label(root, text="Extracted Message:").pack()
        self.output_text = Text(root, height=4, width=50)
        self.output_text.pack()

        # Quit Button
        Button(root, text="Exit", command=root.quit, bg="red", fg="white").pack(pady=10)

        self.image_path = None
        self.key = load_key()

    def load_image(self):
        file_path = filedialog.askopenfilename(filetypes=[("Image Files", "*.png;*.jpg;*.jpeg")])
        if file_path:
            self.image_path = file_path
            self.image_label.config(text=f"Image: {os.path.basename(file_path)}", fg="green")
    
    def hide_message(self):
        if not self.image_path:
            messagebox.showerror("Error", "Please select an image first.")
            return

        message = self.message_entry.get()
        if not message:
            messagebox.showerror("Error", "Message cannot be empty.")
            return

        encrypted_message = encrypt_message(message, self.key).decode('latin-1')
        output_path = "stego_image.png"
        hide_data(self.image_path, encrypted_message, output_path)

    def extract_message(self):
        if not self.image_path:
            messagebox.showerror("Error", "Please select an image first.")
            return

        extracted_message = extract_data(self.image_path, self.key)
        self.output_text.delete(1.0, "end")
        self.output_text.insert("end", extracted_message)

# Run Application
if __name__ == "__main__":
    generate_key()
    root = Tk()
    app = SteganographyApp(root)
    root.mainloop()
