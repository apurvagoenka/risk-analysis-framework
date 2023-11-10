"""
This file contains utility functions which aren't dependent on class objects.
"""
import os
from datetime import datetime
from cryptography.fernet import Fernet


def decrypt(value):
    with open("conf/.key") as priv_key:
        for line in priv_key:
            key = line
    cipher = Fernet(key)
    plaintext = cipher.decrypt(bytes(value, 'utf-8'))
    return bytes(plaintext).decode("utf-8")


def float_range(value, lower_bound, upper_bound):
    return lower_bound <= value <= upper_bound


def max_words(string, words):
    truncated_str = ""
    word_count = 0
    for word in string.split(" "):
        if word_count < words:
            truncated_str += f" {word}"
            word_count += 1
    if len(string.split(" ")) > words:
        return f"{truncated_str.lstrip().rstrip()}..."
    else:
        return truncated_str.lstrip().rstrip()


def get_newest_file(dir, date_string):
    file_date = None
    if files := os.listdir(dir):
        newest = datetime.strptime(files[0].split(".")[0], date_string)
        for file in files:
            file_date = datetime.strptime(file.split(".")[0], date_string)
            if file_date > newest:
                newest = file_date

    return file_date
