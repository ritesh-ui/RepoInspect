import sqlite3
from security import clean_input
import sys

def handle_request():
    # User-controlled input (Explicit Source)
    raw_payload = sys.argv[1]
    
    # We pass it to an external file for sanitization
    safe_payload = clean_input(raw_payload)
    
    # High Confidence Sink Hit (because it originates from an untrusted source)
    conn = sqlite3.connect('test.db')
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM users WHERE target = '{safe_payload}'")
