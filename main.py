import json
import os
import getpass
import hmac
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from argon2 import PasswordHasher

# Generate Secure Keys (If Not Already Saved)
if not os.path.exists("keys.json"):
    keys = {
        "key": os.urandom(32).hex(),  # AES-256 Key
        "hmac_key": os.urandom(32).hex()  # HMAC Key
    }
    with open("keys.json", "w") as f:
        json.dump(keys, f)
else:
    with open("keys.json", "r") as f:
        keys = json.load(f)

# Convert keys back from hex
key = bytes.fromhex(keys["key"])
hmac_key = bytes.fromhex(keys["hmac_key"])
ph = PasswordHasher()  # Argon2 password hasher

# Encrypt data using AES-256-GCM
def encrypt_data(plaintext):
    iv = os.urandom(12)  # Generate IV for each encryption
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext.encode()) + encryptor.finalize()
    return iv + ciphertext, encryptor.tag  # Store IV with encrypted data

# Decrypt data using AES-256-GCM
def decrypt_data(encrypted_data, tag):
    iv = encrypted_data[:12]  # Extract IV
    ciphertext = encrypted_data[12:]  # Extract encrypted content
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag))
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()

# Generate HMAC for data integrity
def generate_hmac(data):
    return hmac.new(hmac_key, data.encode(), hashlib.sha256).hexdigest()

# Verify HMAC to ensure data integrity
def verify_hmac(data, received_hmac):
    return hmac.compare_digest(generate_hmac(data), received_hmac)

# Set & Store Admin Password (If Not Already Set)
def set_admin_password():
    if not os.path.exists("admin_password.txt"):
        password = getpass.getpass("Set Admin Password: ")
        hashed_password = ph.hash(password)
        with open("admin_password.txt", "w") as f:
            f.write(hashed_password)
        print("Admin password set successfully!")

# Verify Admin Password
def verify_admin():
    try:
        with open("admin_password.txt", "r") as f:
            stored_hash = f.read().strip()
        password = getpass.getpass("Enter Admin Password: ")
        if ph.verify(stored_hash, password):
            return True
        else:
            print("Access denied! Incorrect password.")
            return False
    except FileNotFoundError:
        print("Admin password not set! Run the script again to set a password.")
        return False

# Collect and Encrypt Survey Data
def collect_survey():
    print("\nWelcome to the Digital Nomad Sync Survey!\n")
    
    survey_data = {}

    # Basic Info
    survey_data["Gender"] = input("Gender (Male/Female/Other/Prefer not to say): ").strip()
    survey_data["Location"] = input("Where are you staying in Thailand? (e.g., Bangkok, Chiang Mai, etc.): ").strip()
    survey_data["Languages"] = input("What languages do you speak? (Separate by comma): ").strip()
    
    # Availability
    days = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"]
    available_days = []
    print("\nWhich days are you usually available? (Enter Y for yes, N for no)")
    for day in days:
        response = input(f"{day}: ").strip().lower()
        if response == "y":
            available_days.append(day)
    survey_data["Available Days"] = available_days

    # Activity Preferences
    activities = [
        "Playing or Watching Basketball", "Yoga", "Cycling", "Going to the Gym", 
        "Swimming", "Dancing", "Running", "Playing or Listening to Music", "Photography"
    ]
    activity_ratings = {}
    print("\nRate your interest in the following activities (1 = very dislike, 5 = very enjoy)")
    for activity in activities:
        while True:
            try:
                rating = int(input(f"How much do you enjoy {activity}? (1-5): "))
                if 1 <= rating <= 5:
                    activity_ratings[activity] = rating
                    break
                else:
                    print("Please enter a number between 1 and 5.")
            except ValueError:
                print("Invalid input. Please enter a number.")

    survey_data["Activity Ratings"] = activity_ratings

    # GDPR Agreement
    consent = input("\nGDPR Agreement: Do you consent to having this data stored securely? (Y/N): ").strip().lower()
    if consent != "y":
        print("You must consent to proceed.")
        return None

    # Encrypt and save responses
    survey_json = json.dumps(survey_data)
    encrypted_data, tag = encrypt_data(survey_json)
    data_hmac = generate_hmac(survey_json)

    # Store encrypted responses
    with open("survey_responses.enc", "wb") as f:
        f.write(encrypted_data)

    # Store HMAC separately for integrity check
    with open("survey_hmac.txt", "w") as f:
        f.write(data_hmac)

    # Store AES tag separately
    with open("aes_tag.txt", "wb") as f:
        f.write(tag)

    print("\nThank you for completing the survey! Your responses have been securely saved.\n")

# Decrypt and View Survey Data
def view_survey_data():
    try:
        # Read encrypted data
        with open("survey_responses.enc", "rb") as f:
            encrypted_data = f.read()
        
        # Read stored HMAC
        with open("survey_hmac.txt", "r") as f:
            stored_hmac = f.read()

        # Read AES tag
        with open("aes_tag.txt", "rb") as f:
            tag = f.read()

        # Decrypt data
        decrypted_data = decrypt_data(encrypted_data, tag).decode()

        # Verify integrity
        if verify_hmac(decrypted_data, stored_hmac):
            print("\nDecrypted Survey Data:")
            print(json.dumps(json.loads(decrypted_data), indent=4))
        else:
            print("\nData integrity check failed! The survey data may have been tampered with.")

    except FileNotFoundError:
        print("\nNo survey data found.")
    except Exception as e:
        print(f"\nError while decrypting data: {e}")

# CLI Menu
def main():
    set_admin_password()  # Ensure admin password is set
    
    while True:
        print("\n1. Fill out Survey")
        print("2. View Stored Survey Data (Admin Only)")
        print("3. Exit")
        choice = input("\nEnter your choice: ").strip()

        if choice == "1":
            collect_survey()
        elif choice == "2":
            if verify_admin():
                view_survey_data()
        elif choice == "3":
            print("\nGoodbye!")
            break
        else:
            print("Invalid choice. Please enter 1, 2, or 3.")

if __name__ == "__main__":
    main()
