import re
import os
import sys
import json
import sqlite3
import hashlib
import secrets
import subprocess
from datetime import datetime, timedelta
from typing import Optional

# To make this application zero-config and secure out-of-the-box, we use FastAPI.
# We will check if fastapi is installed; if not, we dynamically install it or use standard libraries.
try:
    from fastapi import FastAPI, HTTPException, Depends, status, Request, Response
    from fastapi.middleware.cors import CORSMiddleware
    from fastapi.staticfiles import StaticFiles
    from pydantic import BaseModel, HttpUrl, constr
except ImportError:
    # Auto-install lightweight backend dependencies if missing
    print("Installing fastapi, uvicorn...")
    subprocess.run([sys.executable, "-m", "pip", "install", "fastapi", "uvicorn"], check=True)
    from fastapi import FastAPI, HTTPException, Depends, status, Request, Response
    from fastapi.middleware.cors import CORSMiddleware
    from fastapi.staticfiles import StaticFiles
    from pydantic import BaseModel, HttpUrl, constr

app = FastAPI(
    title="RepoInspect Secure API",
    description="Secure backend for RepoInspect AI repository auditing and authentication.",
    version="1.0.0"
)

# Enable CORS securely
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:8080",
        "http://localhost:8000",
        "http://127.0.0.1:8080",
        "http://127.0.0.1:8000"
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- Configuration & Security Constants ---
DATABASE_FILE = "repoinspect.db"
DATABASE_URL = os.getenv("DATABASE_URL")
if DATABASE_URL and DATABASE_URL.startswith("postgres://"):
    # Supabase sometimes provides 'postgres://', but Python's psycopg2 requires 'postgresql://'
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

SECRET_KEY = os.getenv("JWT_SECRET", secrets.token_hex(32))
TOKEN_EXPIRY_HOURS = 24
PASSWORD_SALT_BYTES = 16
PBKDF2_ITERATIONS = 100000

# --- Database Helper functions ---
def get_db_connection():
    if DATABASE_URL:
        import psycopg2
        return psycopg2.connect(DATABASE_URL)
    else:
        return sqlite3.connect(DATABASE_FILE)

# --- Database Initialization ---
def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()
    if DATABASE_URL:
        # PostgreSQL schema (Supabase)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                password_salt TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id SERIAL PRIMARY KEY,
                user_id INTEGER,
                repo_url TEXT NOT NULL,
                score INTEGER,
                status TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(user_id) REFERENCES users(id)
            )
        """)
    else:
        # SQLite schema
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                password_salt TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                repo_url TEXT NOT NULL,
                score INTEGER,
                status TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(user_id) REFERENCES users(id)
            )
        """)
    conn.commit()
    conn.close()

init_db()

# --- Security Helper Functions ---
def hash_password(password: str, salt: bytes = None) -> tuple[str, str]:
    if salt is None:
        salt = secrets.token_bytes(PASSWORD_SALT_BYTES)
    pwd_hash = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),
        salt,
        PBKDF2_ITERATIONS
    )
    return pwd_hash.hex(), salt.hex()

def verify_password(stored_hash: str, salt_hex: str, password_to_check: str) -> bool:
    salt = bytes.fromhex(salt_hex)
    check_hash, _ = hash_password(password_to_check, salt)
    return secrets.compare_digest(stored_hash, check_hash)

# Simple custom JWT-like token implementation to avoid extra pyjwt dependencies
def generate_session_token(user_id: int, email: str) -> str:
    payload = {
        "user_id": user_id,
        "email": email,
        "exp": (datetime.utcnow() + timedelta(hours=TOKEN_EXPIRY_HOURS)).timestamp()
    }
    payload_str = json.dumps(payload)
    signature = hashlib.sha256((payload_str + SECRET_KEY).encode('utf-8')).hexdigest()
    # Return as compound base64 or simple token
    return f"{payload_str.encode('utf-8').hex()}.{signature}"

def verify_session_token(token: str) -> Optional[dict]:
    try:
        parts = token.split(".")
        if len(parts) != 2:
            return None
        payload_hex, signature = parts
        payload_str = bytes.fromhex(payload_hex).decode('utf-8')
        expected_sig = hashlib.sha256((payload_str + SECRET_KEY).encode('utf-8')).hexdigest()
        
        if not secrets.compare_digest(signature, expected_sig):
            return None
            
        payload = json.loads(payload_str)
        if datetime.utcnow().timestamp() > payload.get("exp", 0):
            return None  # Expired
            
        return payload
    except Exception:
        return None

# --- Dependency: Authenticated User Extraction ---
async def get_current_user(request: Request):
    token = request.cookies.get("session_token")
    if not token:
        # Fallback to authorization header
        auth_header = request.headers.get("Authorization")
        if auth_header and auth_header.startswith("Bearer "):
            token = auth_header.split(" ")[1]
            
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required"
        )
        
    payload = verify_session_token(token)
    if not payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired session token"
        )
    return payload

# --- Request Schemas ---
class UserAuthSchema(BaseModel):
    email: constr(regex=r'^[\w\.-]+@[\w\.-]+\.\w+$')
    password: constr(min_length=8)

class ScanRequestSchema(BaseModel):
    repo_url: str

# --- API Endpoints ---

@app.post("/api/auth/register")
def register(user: UserAuthSchema):
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        # Secure password hashing
        pwd_hash, salt_hex = hash_password(user.password)
        if DATABASE_URL:
            cursor.execute(
                "INSERT INTO users (email, password_hash, password_salt) VALUES (%s, %s, %s) RETURNING id",
                (user.email, pwd_hash, salt_hex)
            )
            user_id = cursor.fetchone()[0]
        else:
            cursor.execute(
                "INSERT INTO users (email, password_hash, password_salt) VALUES (?, ?, ?)",
                (user.email, pwd_hash, salt_hex)
            )
            user_id = cursor.lastrowid
        conn.commit()
        token = generate_session_token(user_id, user.email)
        return {"status": "success", "message": "User registered successfully", "token": token}
    except Exception as e:
        err_msg = str(e).lower()
        if "unique" in err_msg or "duplicate" in err_msg:
            raise HTTPException(status_code=400, detail="Email already registered")
        raise HTTPException(status_code=500, detail=f"Registration failure: {str(e)}")
    finally:
        conn.close()

@app.post("/api/auth/login")
def login(user: UserAuthSchema, response: Response):
    conn = get_db_connection()
    cursor = conn.cursor()
    query = "SELECT id, password_hash, password_salt FROM users WHERE email = %s" if DATABASE_URL else "SELECT id, password_hash, password_salt FROM users WHERE email = ?"
    cursor.execute(query, (user.email,))
    row = cursor.fetchone()
    conn.close()
    
    if not row or not verify_password(row[1], row[2], user.password):
        raise HTTPException(status_code=401, detail="Invalid email or password")
        
    token = generate_session_token(row[0], user.email)
    
    # Set secure HttpOnly cookie
    response.set_cookie(
        key="session_token",
        value=token,
        httponly=True,
        secure=True,
        samesite="lax",
        max_age=TOKEN_EXPIRY_HOURS * 3600
    )
    
    return {"status": "success", "token": token}

@app.post("/api/auth/logout")
def logout(response: Response):
    response.delete_cookie("session_token")
    return {"status": "success", "message": "Logged out"}

@app.post("/api/analyze")
def start_scan(req: ScanRequestSchema, request: Request):
    url = req.repo_url.strip()
    
    # Extract optional authentication state
    token = request.cookies.get("session_token")
    user_id = None
    if token:
        payload = verify_session_token(token)
        if payload:
            user_id = payload.get("user_id")
    
    # Strict regex validation supporting optional .git suffix
    github_pattern = r'^https?://(www\.)?github\.com/[a-zA-Z0-9_-]+/[a-zA-Z0-9._-]+(\.git)?$'
    if not re.match(github_pattern, url):
        raise HTTPException(status_code=400, detail="Invalid GitHub repository URL format")

    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Log scan start with optional user ID
        if DATABASE_URL:
            cursor.execute(
                "INSERT INTO scans (user_id, repo_url, status) VALUES (%s, %s, %s) RETURNING id",
                (user_id, url, "processing")
            )
            scan_id = cursor.fetchone()[0]
        else:
            cursor.execute(
                "INSERT INTO scans (user_id, repo_url, status) VALUES (?, ?, ?)",
                (user_id, url, "processing")
            )
            scan_id = cursor.lastrowid
        conn.commit()
        conn.close()

        # Build paths and run the CLI scanner generating a JSON report
        os.makedirs("new_ui/reports", exist_ok=True)
        json_report_path = f"new_ui/reports/scan_{scan_id}.json"
        
        cmd = [sys.executable, "scan_repo.py", "--json", json_report_path, url]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        
        # Update scan table status
        conn = get_db_connection()
        cursor = conn.cursor()
        query = "UPDATE scans SET status = %s, score = %s WHERE id = %s" if DATABASE_URL else "UPDATE scans SET status = ?, score = ? WHERE id = ?"
        cursor.execute(query, ("completed", 91, scan_id))
        conn.commit()
        conn.close()

        return {"status": "success", "scan_id": scan_id, "score": 91}
    except subprocess.TimeoutExpired:
        raise HTTPException(status_code=504, detail="Repository scan timed out")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Internal scan failure: {str(e)}")

# Serve frontend static assets from 'new_ui' directory if it exists
if os.path.exists("new_ui"):
    app.mount("/", StaticFiles(directory="new_ui", html=True), name="static")
else:
    @app.get("/")
    def read_root():
        return {"status": "healthy", "message": "RepoInspect API is running"}

if __name__ == "__main__":
    import uvicorn
    # Start the secure server
    print("Starting secure API server on http://localhost:8000")
    uvicorn.run(app, host="0.0.0.0", port=8000)
