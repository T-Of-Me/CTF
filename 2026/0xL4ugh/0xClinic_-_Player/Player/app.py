from fastapi import FastAPI, Request, Response
from urllib.request import urlretrieve
from urllib.parse import urlsplit
import subprocess
import sqlite3
import json
from utils.db import getDB
from utils.auth import create_token,require_auth
from utils.config import PROHIBITED_EXTENSIONS,UPLOADS_DIR,DATA_DIR
from utils.db import initDB
from utils.regex import search
from os import environ
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from pathlib import Path
import sys
from secrets import token_urlsafe


sys.stdout = sys.stdout
sys.stderr = sys.stderr

initDB()

JWT_SECRET = token_urlsafe(32)


UPLOADS_DIR.mkdir(exist_ok=True)
DATA_DIR.mkdir(exist_ok=True)

try:
    ADMIN_KEY = environ["ADMIN_KEY"]
except KeyError:
    exit("[!] ADMIN_KEY not set in environment variables.")

app = FastAPI(title="0xClinic API", description="API for 0xClinic application", version="1.0.0")
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="/app/html")

@app.middleware("http")
async def add_no_cache_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'

    return response


@app.get("/health")
async def health(request: Request, test: str = '{"context": {"Check": "Test"}}'):
    if request.cookies.get("ADMIN_KEY", "") != environ.get("ADMIN_KEY", ""):
        return Response(content="Unauthorized", status_code=401)
    try:
        test = json.loads(test)
    except:
        test = {"context": {"Check": "Test"}}
    
    context = test|{"name": "health.html", "request": request}
    if 'headers' not in context:
        context['headers'] = {}
    context['headers']['Content-Security-Policy'] = ("default-src 'self'; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://cdn.tailwindcss.com; "
        "font-src 'self' https://fonts.gstatic.com; "
        "img-src 'self' data:; "
        "object-src 'none'; "
        "base-uri 'self'; "
        "form-action 'self';")
    return templates.TemplateResponse(**context)

@app.get("/")
async def read_root():
    return {"message": "Welcome to the 0xClinic API"}

@app.post("/register")
async def register(request: Request):
    data = await request.json()
    
    username = data.get("username")
    national_id = data.get("national_id")
    password = national_id
    name = data.get("name")
    email = data.get("email")
    date_of_birth = data.get("date_of_birth")
    governrate = data.get("governrate")
    gender = data.get("gender")
    
    if any([not username, not password, not name, not email, not date_of_birth, not governrate, gender is None]):
        return Response(content=json.dumps({"status": "error", "message": "Missing required fields"}), status_code=400, media_type="application/json")
    
    if not national_id or len(national_id) != 14 or not national_id.isdigit():
        return Response(content=json.dumps({"status": "error", "message": "Invalid national ID format"}), status_code=400, media_type="application/json")
    
    dbConn = getDB()
    dbConn.row_factory = sqlite3.Row
    cursor = dbConn.cursor()
    
    cursor.execute("SELECT COUNT(*) FROM users WHERE role='patient'")
    count = cursor.fetchone()[0]
    patient_id = f"P{str(count + 1).zfill(3)}"

    try:
        cursor.execute(
            """
            INSERT INTO users (user_id, username, password, name, date_of_birth, email, governrate, gender, role)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (patient_id, username, password, name, date_of_birth, email, governrate, gender, "patient")
        )
        dbConn.commit()
    except sqlite3.IntegrityError as e:
        dbConn.rollback()
        msg = str(e).lower()
        if "username" in msg:
            message = "Username already exists"
        elif "password" in msg:
            message = "National ID already registered"
        else:
            message = "Duplicate entry"
        dbConn.close()
        return Response(content=json.dumps({"status": "error", "message": message}), status_code=409, media_type="application/json")
    dbConn.close()
    
    DIAGNOSES_FILE = Path(f"data/{username}")
    DIAGNOSES_FILE.touch()
    
    return {"status": "success", "message": "The password has been sent to your email", "patient_id": patient_id}

@app.post("/login")
async def login(request: Request, response: Response):
    data = await request.json()
    
    dbConn = getDB()
    dbConn.row_factory = sqlite3.Row
    cursor = dbConn.cursor()

    cursor.execute("SELECT * FROM users WHERE username=? AND password=?", (data['username'], data['password']))
    user = cursor.fetchone()
    dbConn.close()
    
    if user:
        session_token = create_token(user,JWT_SECRET)

        response.set_cookie(key="auth", value=session_token, httponly=True)
        response.headers["Location"] = f"/dashboard"
        response.status_code = 302
        return response
    
    else:
        return Response(content=json.dumps({"status": "error", "message": "Invalid credentials"}), status_code=401, media_type="application/json")

@app.post("/upload-document")
@require_auth(JWT_SECRET)
async def upload_document(request: Request, patient_id: str = None):
    if not request.state.user or request.state.user.get("role") != "doctor":
        return Response(content=json.dumps({"status": "error", "message": "Unauthorized: Doctor access required"}), status_code=403, media_type="application/json")

    try:
        data = await request.json()
    except Exception:
        return Response(
            content=json.dumps({"status": "error", "message": "Invalid JSON payload"}),
            status_code=400,
            media_type="application/json",
        )

    filename = data.get("filename")
    file_url = data.get("file_url")

    if not filename or not file_url:
        return Response(
            content=json.dumps({"status": "error", "message": "Missing required fields"}),
            status_code=400,
            media_type="application/json",
        )

    file_ext = Path(filename).suffix.lower()
    if file_ext in PROHIBITED_EXTENSIONS:
        return Response(
            content=json.dumps({
                "status": "error",
                "message": "File type not allowed.",
            }),
            status_code=400,
            media_type="application/json",
        )
    
    if urlsplit(file_url).scheme in ["data","http","https","ftp"]:
        return Response(
            content=json.dumps({"status": "error", "message": "Only file:// URLs are allowed"}),
            status_code=400,
            media_type="application/json",
        )
    urlretrieve(file_url, UPLOADS_DIR / filename)
    return {
        "status": "success",
        "message": "Document reference accepted",
        "filename": filename,
        "file_url": file_url,
    }

@app.post("/send-message")
@require_auth(JWT_SECRET)
async def send_message(request: Request):
    if not request.state.user:
        return Response(
            content=json.dumps({"status": "error", "message": "Unauthorized"}),
            status_code=401,
            media_type="application/json"
        )
    
    if not request.state.user.get("verified", False):
        return Response(
            content=json.dumps({"status": "error", "message": "Account not verified"}),
            status_code=403,
            media_type="application/json"
        )

    assignee = "general"
    data = await request.json()
    message = data.get("message")
    illness = data.get("Illness")

    if not message:
        return Response(
            content=json.dumps({"status": "error", "message": "Message cannot be empty"}),
            status_code=400,
            media_type="application/json"
        )

    username = request.state.user.get("username")

    if illness:
        data_file = DATA_DIR / username

        with open(data_file, "r") as f:
            text = f.read()
        try:
            m = search(illness, text)
        except Exception:
            m = None

        if m:
            start = text.rfind("\n", 0, m.start()) + 1
            end = text.find("\n", m.end())
            if end == -1:
                end = len(text)
            line = text[start:end]
            if "by" in line:
                parts = line.split("by")
                doctor = parts[1].strip()
                assignee = doctor

    dbConn = getDB()
    cursor = dbConn.cursor()

    cursor.execute(
        """
        INSERT INTO messages (username, message, assignee)
        VALUES (?, ?, ?)
        """,
        (username, message, assignee)
    )
    dbConn.commit()
    dbConn.close()

    return {"status": "success", "message": "Message sent successfully"}

@app.post("/profile")
@require_auth(JWT_SECRET)
async def update_profile(request: Request):
    """Update user profile: name, email, username, and national_id."""
    username = request.state.user.get("username")
    if not username or not request.state.user.get("id"):
        return Response(
            content=json.dumps({"status": "error", "message": "Unauthorized"}),
            status_code=401,
            media_type="application/json"
        )

    data = await request.json()
    new_name = data.get("name")
    new_email = data.get("email")
    new_username = data.get("username")

    if not new_name or not new_email or not new_username:
        return Response(
            content=json.dumps({"status": "error", "message": "Missing required fields"}),
            status_code=400,
            media_type="application/json"
        )

    dbConn = getDB()
    dbConn.row_factory = sqlite3.Row
    cursor = dbConn.cursor()

    try:
        cursor.execute(
            "UPDATE users SET name = ?, email = ?, username = ? WHERE user_id = ?",
            (new_name, new_email, new_username, request.state.user.get("id") )
        )
        dbConn.commit()
        
        cursor.execute("SELECT user_id, username, role, verified FROM users WHERE username = ?", (new_username,))
        updated_user = cursor.fetchone()
        dbConn.close()
        

        new_token = create_token(updated_user,JWT_SECRET)
        
        response = Response(
            content=json.dumps({"status": "success", "message": "Profile updated successfully"}),
            status_code=200,
            media_type="application/json"
        )
        response.set_cookie(key="auth", value=new_token, httponly=True)
        return response
    except sqlite3.IntegrityError as e:
        dbConn.rollback()
        dbConn.close()
        msg = str(e).lower()
        if "username" in msg:
            message = "Username already in use"
        elif "password" in msg:
            message = "National ID already registered"
        elif "email" in msg:
            message = "Email already in use"
        else:
            message = "Update failed due to duplicate entry"
        return Response(
            content=json.dumps({"status": "error", "message": message}),
            status_code=409,
            media_type="application/json"
        )
    except Exception as e:
        dbConn.rollback()
        dbConn.close()
        return Response(
            content=json.dumps({"status": "error", "message": f"Update failed: {str(e)}"}),
            status_code=500,
            media_type="application/json"
        )

@app.get("/userdata")
@require_auth(JWT_SECRET)
async def userdate(request: Request):
    return request.state.user

@app.get("/logout")
async def logout():
    resp = Response()
    resp.status_code = 302
    resp.headers["Location"] = "/"
    resp.delete_cookie("auth")
    return resp

@app.get("/test-doctor")
@require_auth(JWT_SECRET)
def test_doctor(request: Request):
    if request.state.user.get("role") == "doctor":
            return {"data": request.state.user}
    
@app.get("/profile/{username}")
@require_auth(JWT_SECRET)
def profile(request: Request, username: str):
    dbConn = getDB()
    cursor = dbConn.cursor()
    cursor.execute("SELECT user_id, username, name, date_of_birth, email, governrate, role, gender FROM users WHERE username=?", (username,))
    user = cursor.fetchone()
    dbConn.close()

    if user:
        full_name = user[2]
        parts = (full_name or "").split(" ", 1)
        first_name = parts[0] if parts and parts[0] else ""
        last_name = parts[1] if len(parts) > 1 else ""
        user_data = {
            "user_id": user[0],
            "username": user[1],
            "name": full_name,
            "first_name": first_name,
            "last_name": last_name,
            "date_of_birth": user[3],
            "email": user[4],
            "governrate": user[5],
            "role": user[6],
            "gender": user[7]
        }
        return {"status": "success", "data": user_data}
    else:
        return Response(
            content=json.dumps({"status": "error", "message": "User not found"}),
            status_code=404,
            media_type="application/json"
        )
    

@app.get("/bot")
def bot():
    subprocess.run(["python3", "./bot.py",JWT_SECRET])
    return {"status": "success", "message": "Bot executed"}