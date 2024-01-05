import random, string
from django.utils.crypto import get_random_string
import hashlib
from .models import User


def generate_unique_username():
    """this method will return a unique username"""
    
    while True:
        username = 'user_' + get_random_string(length=8)
        if not User.objects.filter(username=username).exists():
            return username

def generate_password(length=8):
    """generating a password with specified criteria [a password with given length, 1 lower case, 1 upper case, and 1 special character]"""
    
    uppercase_char = random.choice(string.ascii_uppercase)
    lowercase_char = random.choice(string.ascii_lowercase)
    special_char = random.choice(string.punctuation)

    # generating the remaining characters
    remaining_length = length-3
    remaining_chars = get_random_string(length=remaining_length)

    password = uppercase_char + lowercase_char + special_char + remaining_chars
    return password

def check_is_strong_password(password, length=8):
    if len(password) < length:
        return False
    
    if not any(char.isupper() for char in password) or not any(char.islower() for char in password) or not any(char in string.punctuation for char in password):
        return False
    return True

def store_otp(otp):
    hashed_otp = hashlib.sha256(str(otp).encode()).hexdigest()
    return hashed_otp

def verify_otp(entered_otp, stored_hashed_otp):
    user_provided_hashed_otp = hashlib.sha256(str(entered_otp).encode()).hexdigest()
    return user_provided_hashed_otp == stored_hashed_otp
