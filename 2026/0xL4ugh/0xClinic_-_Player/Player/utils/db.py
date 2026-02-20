import sqlite3
from secrets import token_urlsafe
import os

def getDB():
    db = sqlite3.connect("app.db")
    return db

def initDB():
    dbConn = getDB()
    cursor = dbConn.cursor()
    
    cursor.execute("DROP TABLE IF EXISTS users")
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id TEXT UNIQUE NOT NULL,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL UNIQUE,
        name TEXT NOT NULL,
        date_of_birth TEXT NOT NULL,
        email TEXT NOT NULL,
        governrate TEXT NOT NULL,
        gender INTEGER NOT NULL,
        role TEXT NOT NULL,
        verified INTEGER DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)
    
    cursor.execute("DROP TABLE IF EXISTS messages")
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL,
        message TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

        assignee TEXT not null
    )
    """)
    

    cursor.execute(
        """
        INSERT INTO users (user_id, username, password, name, date_of_birth, email, governrate, gender, role, verified)

        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (f"D{str(1).zfill(3)}", "admin", token_urlsafe(32), "Admin", "1900-01-01", "", "Unknown", 1, "doctor", 1)
    )

    cursor.execute(
            """

            INSERT INTO users (user_id, username, password, name, date_of_birth, email, governrate, gender, role, verified)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (f"P{str(1).zfill(3)}", "patient_test", os.environ.get("test_national_id", "30508011601589"), "Test Patient", "2005-08-01", "", "Gharbiya", "female", "patient", 1)
        )
    
    dbConn.commit()
    dbConn.close()
