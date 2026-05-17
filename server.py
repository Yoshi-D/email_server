"""
server.py — Run this on the SERVER machine (your friend's laptop)
Starts:
  - SMTP server on port 2525
  - POP3 server on port 1100
  - FastAPI on port 8000 (for signup/login)

Requirements: pip install fastapi uvicorn mysql-connector-python
Run: python server.py
"""

import socket
import threading
import datetime
import json
import re
import uvicorn
import mysql.connector
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

# ─────────────────────────────────────────────
# CONFIG
# ─────────────────────────────────────────────
SMTP_HOST = "0.0.0.0"
SMTP_PORT = 2525
POP3_HOST = "0.0.0.0"
POP3_PORT = 1100
API_HOST  = "0.0.0.0"
API_PORT  = 8000

DB_CONFIG = {
    "host":     "localhost",
    "user":     "root",
    "password": "newpassword",
    "database": "email_server"
}

# ─────────────────────────────────────────────
# DB HELPERS (each call gets a fresh cursor to
# avoid "unread result" issues across threads)
# ─────────────────────────────────────────────

def get_db():
    conn = mysql.connector.connect(**DB_CONFIG)
    return conn

def db_query(sql, params=(), fetchone=False, fetchall=False, commit=False):
    conn = get_db()
    cur  = conn.cursor(dictionary=True)
    cur.execute(sql, params)
    result = None
    if fetchone:
        result = cur.fetchone()
    elif fetchall:
        result = cur.fetchall()
    if commit:
        conn.commit()
    cur.close()
    conn.close()
    return result

# ─────────────────────────────────────────────
# DATABASE INIT  (creates tables if missing)
# ─────────────────────────────────────────────

def init_db():
    conn = get_db()
    cur  = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id       INT AUTO_INCREMENT PRIMARY KEY,
            email    VARCHAR(255) UNIQUE NOT NULL,
            password VARCHAR(255) NOT NULL
        )
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS emails (
            id          INT AUTO_INCREMENT PRIMARY KEY,
            sender      VARCHAR(255) NOT NULL,
            recipient   VARCHAR(255) NOT NULL,
            subject     VARCHAR(500) DEFAULT '',
            message     TEXT         ,
            priority    ENUM('low','normal','high') DEFAULT 'normal',
            is_read     TINYINT(1)   DEFAULT 0,
            is_deleted  TINYINT(1)   DEFAULT 0,
            received_at DATETIME     DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.commit()
    cur.close()
    conn.close()
    print("[DB] Tables ready.")

# ─────────────────────────────────────────────
# SMTP SERVER  (mimics RFC 5321 hand­shake)
# Commands: HELO, EHLO, MAIL FROM, RCPT TO,
#           DATA, QUIT, RSET, NOOP
# ─────────────────────────────────────────────

def handle_smtp_client(conn, addr):
    print(f"[SMTP] Connection from {addr}")
    def send(msg):
        conn.sendall((msg + "\r\n").encode())

    send("220 mailserver SMTP Ready")

    state = {
        "helo_done":  False,
        "mail_from":  None,
        "rcpt_to":    [],
        "in_data":    False,
        "data_lines": []
    }

    buffer = ""
    try:
        while True:
            chunk = conn.recv(4096).decode(errors="replace")
            if not chunk:
                break
            buffer += chunk

            while "\r\n" in buffer or "\n" in buffer:
                sep = "\r\n" if "\r\n" in buffer else "\n"
                line, buffer = buffer.split(sep, 1)

                # ── DATA mode: accumulate until lone "."
                if state["in_data"]:
                    if line.strip() == ".":
                        state["in_data"] = False
                        # Parse headers from data_lines
                        raw       = "\n".join(state["data_lines"])
                        subject   = ""
                        priority  = "normal"
                        body_lines = []
                        in_body   = False
                        for dl in state["data_lines"]:
                            if dl == "":
                                in_body = True
                                continue
                            if not in_body:
                                if dl.lower().startswith("subject:"):
                                    subject = dl[8:].strip()
                                elif dl.lower().startswith("x-priority:"):
                                    p = dl.split(":",1)[1].strip().lower()
                                    if p in ("low","high","normal"):
                                        priority = p
                            else:
                                body_lines.append(dl)
                        body = "\n".join(body_lines)

                        # Store one copy per recipient
                        for rcpt in state["rcpt_to"]:
                            # Check recipient exists
                            user = db_query(
                                "SELECT id FROM users WHERE email=%s",
                                (rcpt,), fetchone=True
                            )
                            if user:
                                db_query(
                                    """INSERT INTO emails
                                       (sender,recipient,subject,message,priority,received_at)
                                       VALUES (%s,%s,%s,%s,%s,NOW())""",
                                    (state["mail_from"], rcpt, subject, body, priority),
                                    commit=True
                                )
                                print(f"[SMTP] Stored email → {rcpt}")
                            else:
                                print(f"[SMTP] Unknown recipient {rcpt}, discarding")

                        send("250 OK: message queued")
                        # Reset for next message
                        state["mail_from"]  = None
                        state["rcpt_to"]    = []
                        state["data_lines"] = []
                    else:
                        # Dot-stuffing: leading ".." → "."
                        state["data_lines"].append(line[1:] if line.startswith("..") else line)
                    continue

                # ── Command mode
                cmd = line.strip().upper()

                if cmd in ("HELO", "") or cmd.startswith("HELO ") or cmd.startswith("EHLO "):
                    state["helo_done"] = True
                    domain = line.strip().split(None,1)[1] if " " in line.strip() else "unknown"
                    send(f"250 Hello {domain}, pleased to meet you")

                elif cmd.startswith("MAIL FROM"):
                    if not state["helo_done"]:
                        send("503 Bad sequence: send HELO first")
                        continue
                    m = re.search(r"<(.+?)>", line) or re.search(r"FROM:\s*(\S+)", line, re.I)
                    if m:
                        state["mail_from"] = m.group(1)
                        send("250 OK")
                    else:
                        send("501 Syntax error in MAIL FROM")

                elif cmd.startswith("RCPT TO"):
                    if not state["mail_from"]:
                        send("503 Bad sequence: send MAIL FROM first")
                        continue
                    m = re.search(r"<(.+?)>", line) or re.search(r"TO:\s*(\S+)", line, re.I)
                    if m:
                        state["rcpt_to"].append(m.group(1))
                        send("250 OK")
                    else:
                        send("501 Syntax error in RCPT TO")

                elif cmd == "DATA":
                    if not state["rcpt_to"]:
                        send("503 Bad sequence: send RCPT TO first")
                        continue
                    state["in_data"] = True
                    send("354 Start mail input; end with <CRLF>.<CRLF>")

                elif cmd == "QUIT":
                    send("221 Bye")
                    return

                elif cmd == "RSET":
                    state["mail_from"]  = None
                    state["rcpt_to"]    = []
                    state["in_data"]    = False
                    state["data_lines"] = []
                    send("250 OK")

                elif cmd == "NOOP":
                    send("250 OK")

                else:
                    send(f"500 Unknown command: {line.strip()[:40]}")

    except Exception as e:
        print(f"[SMTP] Error with {addr}: {e}")
    finally:
        conn.close()
        print(f"[SMTP] Disconnected {addr}")


def start_smtp():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((SMTP_HOST, SMTP_PORT))
    srv.listen(10)
    print(f"[SMTP] Listening on {SMTP_HOST}:{SMTP_PORT}")
    while True:
        conn, addr = srv.accept()
        threading.Thread(target=handle_smtp_client, args=(conn, addr), daemon=True).start()


# ─────────────────────────────────────────────
# POP3 SERVER  (mimics RFC 1939)
# States: AUTHORIZATION → TRANSACTION → UPDATE
# Commands: USER, PASS, STAT, LIST, RETR, DELE,
#           RSET, NOOP, QUIT
# ─────────────────────────────────────────────

def handle_pop3_client(conn, addr):
    print(f"[POP3] Connection from {addr}")
    def send(msg):
        conn.sendall((msg + "\r\n").encode())

    send("+OK POP3 server ready")

    state      = "AUTHORIZATION"   # → TRANSACTION → UPDATE
    user_email = None
    session_emails = []            # list of email dicts for this session
    deleted    = set()             # indices (1-based) marked for deletion

    buffer = ""
    try:
        while True:
            chunk = conn.recv(4096).decode(errors="replace")
            if not chunk:
                break
            buffer += chunk

            while "\r\n" in buffer or "\n" in buffer:
                sep = "\r\n" if "\r\n" in buffer else "\n"
                line, buffer = buffer.split(sep, 1)
                cmd_parts = line.strip().split(None, 1)
                if not cmd_parts:
                    continue
                cmd  = cmd_parts[0].upper()
                arg  = cmd_parts[1] if len(cmd_parts) > 1 else ""

                # ── AUTHORIZATION state
                if state == "AUTHORIZATION":
                    if cmd == "USER":
                        user = db_query(
                            "SELECT id FROM users WHERE email=%s", (arg,), fetchone=True
                        )
                        if user:
                            user_email = arg
                            send(f"+OK {arg} found")
                        else:
                            send("-ERR no such user")

                    elif cmd == "PASS":
                        if not user_email:
                            send("-ERR send USER first")
                            continue
                        user = db_query(
                            "SELECT id FROM users WHERE email=%s AND password=%s",
                            (user_email, arg), fetchone=True
                        )
                        if user:
                            # Load inbox into session
                            session_emails = db_query(
                                """SELECT id,sender,recipient,subject,message,
                                          priority,is_read,received_at
                                   FROM emails
                                   WHERE recipient=%s AND is_deleted=0
                                   ORDER BY received_at DESC""",
                                (user_email,), fetchall=True
                            ) or []
                            state = "TRANSACTION"
                            send(f"+OK maildrop ready, {len(session_emails)} messages")
                        else:
                            send("-ERR invalid credentials")
                            user_email = None

                    elif cmd == "QUIT":
                        send("+OK bye")
                        return
                    else:
                        send("-ERR unknown command")

                # ── TRANSACTION state
                elif state == "TRANSACTION":
                    if cmd == "STAT":
                        active = [e for i,e in enumerate(session_emails,1) if i not in deleted]
                        total_size = sum(len((e.get("message") or "").encode()) for e in active)
                        send(f"+OK {len(active)} {total_size}")

                    elif cmd == "LIST":
                        if arg:
                            try:
                                idx = int(arg)
                                if 1 <= idx <= len(session_emails) and idx not in deleted:
                                    size = len((session_emails[idx-1].get("message") or "").encode())
                                    send(f"+OK {idx} {size}")
                                else:
                                    send("-ERR no such message")
                            except ValueError:
                                send("-ERR invalid argument")
                        else:
                            active = [(i+1, e) for i,e in enumerate(session_emails) if (i+1) not in deleted]
                            send(f"+OK {len(active)} messages")
                            for idx, e in active:
                                size = len((e.get("message") or "").encode())
                                send(f"{idx} {size}")
                            send(".")

                    elif cmd == "RETR":
                        try:
                            idx = int(arg)
                            if 1 <= idx <= len(session_emails) and idx not in deleted:
                                e    = session_emails[idx-1]
                                body = e.get("message") or ""
                                size = len(body.encode())
                                send(f"+OK {size} octets")
                                # Emit RFC 2822-style headers
                                send(f"From: {e['sender']}")
                                send(f"To: {e['recipient']}")
                                send(f"Subject: {e.get('subject','')}")
                                send(f"X-Priority: {e.get('priority','normal')}")
                                recv_at = e.get("received_at")
                                send(f"Date: {recv_at}")
                                send("")   # blank line = start of body
                                for bl in body.split("\n"):
                                    # dot-stuffing
                                    send(("." + bl) if bl.startswith(".") else bl)
                                send(".")
                                # Mark as read
                                db_query(
                                    "UPDATE emails SET is_read=1 WHERE id=%s",
                                    (e["id"],), commit=True
                                )
                            else:
                                send("-ERR no such message")
                        except (ValueError, IndexError):
                            send("-ERR invalid argument")

                    elif cmd == "DELE":
                        try:
                            idx = int(arg)
                            if 1 <= idx <= len(session_emails) and idx not in deleted:
                                deleted.add(idx)
                                send(f"+OK message {idx} deleted")
                            else:
                                send("-ERR no such message")
                        except ValueError:
                            send("-ERR invalid argument")

                    elif cmd == "RSET":
                        deleted.clear()
                        send("+OK")

                    elif cmd == "NOOP":
                        send("+OK")

                    elif cmd == "QUIT":
                        state = "UPDATE"
                        # Commit deletions
                        for idx in deleted:
                            eid = session_emails[idx-1]["id"]
                            db_query(
                                "UPDATE emails SET is_deleted=1 WHERE id=%s",
                                (eid,), commit=True
                            )
                        send(f"+OK {len(deleted)} messages deleted")
                        return

                    else:
                        send("-ERR unknown command")

    except Exception as e:
        print(f"[POP3] Error with {addr}: {e}")
    finally:
        conn.close()
        print(f"[POP3] Disconnected {addr}")


def start_pop3():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((POP3_HOST, POP3_PORT))
    srv.listen(10)
    print(f"[POP3] Listening on {POP3_HOST}:{POP3_PORT}")
    while True:
        conn, addr = srv.accept()
        threading.Thread(target=handle_pop3_client, args=(conn, addr), daemon=True).start()


# ─────────────────────────────────────────────
# FASTAPI  (signup / login only)
# ─────────────────────────────────────────────

app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class SignupRequest(BaseModel):
    email: str
    password: str

class LoginRequest(BaseModel):
    email: str
    password: str

@app.post("/signup")
def signup(data: SignupRequest):
    existing = db_query("SELECT id FROM users WHERE email=%s", (data.email,), fetchone=True)
    if existing:
        raise HTTPException(status_code=400, detail="User already exists")
    db_query(
        "INSERT INTO users (email, password) VALUES (%s, %s)",
        (data.email, data.password), commit=True
    )
    return {"message": "User created successfully"}

@app.post("/login")
def login(data: LoginRequest):
    user = db_query(
        "SELECT * FROM users WHERE email=%s AND password=%s",
        (data.email, data.password), fetchone=True
    )
    if not user:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    return {"message": "Login successful"}

# ─────────────────────────────────────────────
# ENTRY POINT
# ─────────────────────────────────────────────

if __name__ == "__main__":
    init_db()
    threading.Thread(target=start_smtp, daemon=True).start()
    threading.Thread(target=start_pop3, daemon=True).start()
    print(f"[API] Starting FastAPI on {API_HOST}:{API_PORT}")
    uvicorn.run(app, host=API_HOST, port=API_PORT)
