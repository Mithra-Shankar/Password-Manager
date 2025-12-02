import string
import random

def generate_password(length=12):
    ALL_CHARS = string.ascii_letters + string.digits + "@#$%&*"
    password_list = [
        random.choice(string.ascii_lowercase),
        random.choice(string.ascii_uppercase),
        random.choice(string.digits),
        random.choice("@#$%&*")
    ]
    
    remaining_length = length - len(password_list)
    password_list.extend(random.choices(ALL_CHARS, k=remaining_length))
    random.shuffle(password_list)
    return "".join(password_list)