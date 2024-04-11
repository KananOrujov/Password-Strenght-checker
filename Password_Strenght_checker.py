import tkinter as tk
from tkinter import ttk
import re
import math
import requests


def check_password_strength():
    password = entry_password.get()
    strength, recommendation = get_password_strength(password)
    strength_label.config(text=strength, foreground=strength_colors[strength])
    recommendation_text.delete(1.0, tk.END)
    recommendation_text.insert(tk.END, recommendation)
    recommendation_text.tag_configure("center", justify='center')
    recommendation_text.tag_add("center", 1.0, tk.END)
    time_to_break_label.config(text=format_time(estimate_time_to_break(calculate_entropy(password))))

    is_breached = check_breached_password(password)
    breached_label.config(text="Password breached: " + ("Yes" if is_breached else "No"),
                          foreground=("red" if is_breached else "green"))


def get_password_strength(password):
    if len(password) == 0:
        return "Password cannot be blank", ""
    elif len(password) < 4:
        return "Very weak", "Try adding more characters."
    else:
        strength = 0
        if re.search(r'[0-9]', password):
            strength += 1
        if re.search(r'[a-z]', password) and re.search(r'[A-Z]', password):
            strength += 1
        if re.search(r'[!@#$%^&*()_+]', password):
            strength += 1
        if len(password) > 8:
            strength += 1

        if strength == 0:
            return "Very weak", "Try using a mix of upper and lower case letters, numbers, and special characters."
        elif strength == 1:
            return "Weak", "Consider using a longer password with a mix of character types."
        elif strength == 2:
            return "Medium", "You're on the right track, but a longer password with more complexity is better."
        elif strength == 3:
            return "Strong", "Your password is strong, but you can still make it even more secure."
        else:
            return "Very strong", "Congratulations! Your password is very secure."


def calculate_entropy(password):
    character_set_size = 0
    if re.search(r'[0-9]', password):
        character_set_size += 10
    if re.search(r'[a-z]', password):
        character_set_size += 26
    if re.search(r'[A-Z]', password):
        character_set_size += 26
    if re.search(r'[!@#$%^&*()_+]', password):
        character_set_size += 10

    length = len(password)
    return math.log2(character_set_size) * length


def estimate_time_to_break(entropy):
    # Assumptions for time calculation (adjust as needed)
    password_attempts_per_second = 1000000000  # 1 billion attempts per second
    seconds_in_a_year = 31536000  # Approximately 1 year in seconds

    return (2 ** entropy) / (password_attempts_per_second * seconds_in_a_year)


def format_time(seconds):
    days, remainder = divmod(seconds, 86400)
    hours, remainder = divmod(remainder, 3600)
    minutes, seconds = divmod(remainder, 60)
    return f"{int(days)} days {int(hours)} hours {int(minutes)} minutes {int(seconds)} seconds"


def check_breached_password(password):
    # Use the "Have I Been Pwned" API to check if the password has been breached
    # The API provides a list of breached passwords (hashed), and we'll check if the hash of the given password is in the list
    url = f"https://api.pwnedpasswords.com/range/{hash_password_prefix(password)}"
    response = requests.get(url)

    if response.status_code == 200:
        hash_suffix = hash_password_suffix(password)
        # Check if the hash of the password's suffix is in the response
        return hash_suffix in response.text
    else:
        # If the API request fails, return False (not breached)
        return False


def hash_password_prefix(password):
    # Hash the password prefix (first 5 characters) using SHA-1
    hashed = hashlib.sha1(password.encode()).hexdigest().upper()
    return hashed[:5]


def hash_password_suffix(password):
    # Hash the password suffix (excluding the first 5 characters) using SHA-1
    hashed = hashlib.sha1(password.encode()).hexdigest().upper()
    return hashed[5:]


gui = tk.Tk()
gui.geometry('400x440+700+250')
gui.title('Password Strength Checker')

style = ttk.Style()
style.configure("TLabel", background="#F3EFEF", font=('Arial', 12))
style.configure("TButton", background="#4CAF50", font=('Arial', 12), foreground="white")

frame = ttk.Frame(gui)
frame.grid(row=0, column=0, padx=20, pady=20)

label_instruction = ttk.Label(frame, text="Enter your password:")
label_instruction.grid(row=0, column=0, columnspan=2)

entry_password = ttk.Entry(frame, show="*")
entry_password.grid(row=1, column=0, columnspan=2, pady=5)

check_button = ttk.Button(frame, text="Check", command=check_password_strength)
check_button.grid(row=2, column=0, columnspan=2, pady=10)

strength_label = ttk.Label(frame, text="", font=('Arial', 14))
strength_label.grid(row=3, column=0, columnspan=2)

recommendation_label = ttk.Label(frame, text="Recommendation:", font=('Arial', 12))
recommendation_label.grid(row=4, column=0, columnspan=2, pady=5)

recommendation_text = tk.Text(frame, height=4, width=40, font=('Arial', 12), wrap='word')
recommendation_text.grid(row=5, column=0, columnspan=2, pady=5)

breached_label = ttk.Label(frame, text="", font=('Arial', 12))
breached_label.grid(row=6, column=0, columnspan=2)

time_to_break_label = ttk.Label(frame, text="", font=('Arial', 12))
time_to_break_label.grid(row=7, column=0, columnspan=2)

strength_colors = {
    'Password cannot be blank': 'red',
    'Very weak': 'red',
    'Weak': 'orange',
    'Medium': 'gold',
    'Strong': 'green',
    'Very strong': 'green'
}

gui.mainloop()
