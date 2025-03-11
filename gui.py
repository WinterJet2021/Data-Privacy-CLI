import json
import os
import tkinter as tk
from tkinter import ttk, messagebox
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# Generate AES key & IV
key = os.urandom(32)
iv = os.urandom(12)

# Encrypt survey data
def encrypt_data(plaintext):
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext.encode()) + encryptor.finalize()
    return ciphertext, encryptor.tag

# Function to collect and save survey responses
def submit_survey():
    data = {
        "Gender": gender_var.get(),
        "Location": location_entry.get(),
        "Languages": language_entry.get(),
        "Available Days": [day for day, var in checkboxes.items() if var.get()],
        "Basketball": basketball_var.get(),
        "Yoga": yoga_var.get(),
        "Cycling": cycling_var.get()
    }

    # Convert data to JSON and encrypt
    survey_json = json.dumps(data)
    encrypted_data, tag = encrypt_data(survey_json)

    with open("survey_responses.json", "wb") as f:
        f.write(encrypted_data)

    messagebox.showinfo("Success", "Survey Submitted Securely!")

# Create GUI Window
root = tk.Tk()
root.title("Nomad Sync Survey")
root.geometry("400x500")

# Gender Selection
tk.Label(root, text="Gender:").pack()
gender_var = tk.StringVar(value="Prefer not to say")
gender_options = ["Male", "Female", "Other", "Prefer not to say"]
gender_menu = ttk.Combobox(root, textvariable=gender_var, values=gender_options)
gender_menu.pack()

# Location
tk.Label(root, text="Where are you staying in Thailand?").pack()
location_entry = tk.Entry(root)
location_entry.pack()

# Language
tk.Label(root, text="What language do you speak?").pack()
language_entry = tk.Entry(root)
language_entry.pack()

# Days Available
tk.Label(root, text="Available Days:").pack()
checkboxes = {}
days = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"]
for day in days:
    var = tk.BooleanVar()
    checkboxes[day] = var
    tk.Checkbutton(root, text=day, variable=var).pack()

# Activity Ratings
tk.Label(root, text="Rate Activities (1-5):").pack()
basketball_var = tk.IntVar(value=3)
tk.Label(root, text="Basketball:").pack()
ttk.Scale(root, from_=1, to=5, variable=basketball_var, orient="horizontal").pack()

yoga_var = tk.IntVar(value=3)
tk.Label(root, text="Yoga:").pack()
ttk.Scale(root, from_=1, to=5, variable=yoga_var, orient="horizontal").pack()

cycling_var = tk.IntVar(value=3)
tk.Label(root, text="Cycling:").pack()
ttk.Scale(root, from_=1, to=5, variable=cycling_var, orient="horizontal").pack()

# Submit Button
tk.Button(root, text="Submit", command=submit_survey).pack()

# Run GUI
root.mainloop()
