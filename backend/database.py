# database.py

import sqlite3

DB_NAME = "phishing.db"

def get_connection():
    return sqlite3.connect(DB_NAME)

def create_table():
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scan_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            content TEXT,
            links TEXT,
            verdict TEXT,
            score INTEGER,
            reasons TEXT
        )
    """)

    conn.commit()
    conn.close()

def insert_log(content, links, verdict, score, reasons):
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO scan_logs (content, links, verdict, score, reasons)
        VALUES (?, ?, ?, ?, ?)
    """, (
        content,
        ", ".join(links),
        verdict,
        score,
        "; ".join(reasons)
    ))

    conn.commit()
    conn.close()

def fetch_all_logs():
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM scan_logs ORDER BY id DESC")
    rows = cursor.fetchall()

    conn.close()
    return rows

def fetch_log_by_id(log_id):
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM scan_logs WHERE id = ?", (log_id,))
    row = cursor.fetchone()

    conn.close()
    return row
