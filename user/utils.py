import random, string
from django.utils.crypto import get_random_string


def generate_unique_username():
    return 'user_' + get_random_string(length=6)

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
