import re
import tkinter as tk
from tkinter import messagebox, ttk
import pyperclip

def assess_password_strength(password):
    length_criteria = len(password) >= 8
    uppercase_criteria = re.search(r'[A-Z]', password) is not None
    lowercase_criteria = re.search(r'[a-z]', password) is not None
    number_criteria = re.search(r'[0-9]', password) is not None
    special_char_criteria = re.search(r'[@$!%*?&]', password) is not None

    criteria_met = sum([length_criteria, uppercase_criteria, lowercase_criteria,
                        number_criteria, special_char_criteria])

    if criteria_met == 5:
        strength = "Very Strong"
    elif criteria_met == 4:
        strength = "Strong"
    elif criteria_met == 3:
        strength = "Moderate"
    elif criteria_met == 2:
        strength = "Weak"
    else:
        strength = "Very Weak"

    feedback = []
    if not length_criteria:
        feedback.append("Password should be at least 8 characters long.")
    if not uppercase_criteria:
        feedback.append("Password should contain at least one uppercase letter.")
    if not lowercase_criteria:
        feedback.append("Password should contain at least one lowercase letter.")
    if not number_criteria:
        feedback.append("Password should contain at least one number.")
    if not special_char_criteria:
        feedback.append("Password should contain at least one special character (e.g., @$!%*?&).")

    return strength, feedback

def evaluate_password(event=None):
    password = entry.get()
    strength, feedback = assess_password_strength(password)

    result_label.config(text=f"Password Strength: {strength}")

    feedback_text.delete(1.0, tk.END)
    if feedback:
        feedback_text.insert(tk.END, "Feedback:\n")
        for line in feedback:
            feedback_text.insert(tk.END, f"- {line}\n")
    else:
        feedback_text.insert(tk.END, "Your password meets all strength criteria!")

def on_password_change(event):
    password = entry.get()
    strength, feedback = assess_password_strength(password)
    result_label.config(text=f"Password Strength: {strength}")
    update_strength_meter(strength)
    feedback_text.delete(1.0, tk.END)
    if feedback:
        feedback_text.insert(tk.END, "Feedback:\n")
        for line in feedback:
            feedback_text.insert(tk.END, f"- {line}\n")
    else:
        feedback_text.insert(tk.END, "Your password meets all strength criteria!")

def update_strength_meter(strength):
    if strength == "Very Strong":
        strength_meter['value'] = 100
    elif strength == "Strong":
        strength_meter['value'] = 80
    elif strength == "Moderate":
        strength_meter['value'] = 60
    elif strength == "Weak":
        strength_meter['value'] = 40
    else:
        strength_meter['value'] = 20

def copy_password_to_clipboard():
    password = entry.get()
    pyperclip.copy(password)
    messagebox.showinfo("Password Copied", "The password has been copied to the clipboard.")

# Set up the main application window
root = tk.Tk()
root.title("Advanced Password Strength Checker")
root.geometry("500x400")
root.config(bg="#1e1e1e")

# Create a frame for the input
input_frame = tk.Frame(root, bg="#2e2e2e")
input_frame.pack(pady=20, padx=20, fill="x")

# Create widgets
entry_label = tk.Label(input_frame, text="Enter a password:", bg="#2e2e2e", fg="#f0f0f0", font=("Helvetica", 12))
entry = tk.Entry(input_frame, width=30, font=("Helvetica", 12), show="*")
copy_button = tk.Button(input_frame, text="Copy", command=copy_password_to_clipboard, font=("Helvetica", 12),
                        bg="#2980b9", fg="#f0f0f0", relief="flat")

entry_label.grid(row=0, column=0, pady=10, padx=10, sticky="e")
entry.grid(row=0, column=1, pady=10, padx=10)
copy_button.grid(row=1, column=1, pady=10)

# Bind the Enter key and password changes to functions
entry.bind('<Return>', evaluate_password)
entry.bind('<KeyRelease>', on_password_change)

# Create a frame for the output
output_frame = tk.Frame(root, bg="#2e2e2e")
output_frame.pack(pady=10, padx=20, fill="both", expand=True)

# Strength meter
strength_meter = ttk.Progressbar(output_frame, orient="horizontal", length=200, mode="determinate")
strength_meter.pack(pady=10)

result_label = tk.Label(output_frame, text="", bg="#2e2e2e", fg="#f0f0f0", font=("Helvetica", 14, "bold"))
feedback_text = tk.Text(output_frame, width=50, height=10, wrap="word", font=("Helvetica", 10), bg="#3e3e3e",
                        fg="#f0f0f0", relief="flat")

result_label.pack(pady=10)
feedback_text.pack(pady=10, padx=10, fill="both", expand=True)

# Start the main event loop
root.mainloop()