import re

def clean_input(raw_data):
    # This is a custom enterprise class sanitizer!
    # It removes all malicious characters.
    # The Zero-Shot LLM fails here because it can't read it.
    # The new Agent WILL read this file!
    clean = re.sub(r"[^a-zA-Z0-9_]", "", raw_data)
    return clean
