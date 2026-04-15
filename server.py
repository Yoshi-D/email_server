"""
server.py — Run this on the SERVER machine (your friend's laptop)
Starts:
  - SMTP server on port 2525
  - POP3 server on port 1100
  - FastAPI on port 8000 (for signup/login)

Requirements: pip install fastapi uvicorn mysql-connector-python
Run: python server.py

Encryption notes
────────────────
  WIRE_SHIFT  — Caesar shift applied by the client before sending over TCP.
                The server *decrypts* incoming SMTP fields with this key.
  DB_SHIFT    — A second Caesar shift applied by the server before writing
                to MySQL.  The server *decrypts* on read before returning
                data over POP3 (which the client then decrypts again with
                WIRE_SHIFT before showing to the browser).

  Both shifts must be kept in sync with client_proxy.py.

  Only printable ASCII (0x20–0x7E) is shifted; CRLF, dots, and any
  non-ASCII bytes are left untouched so SMTP/POP3 framing is never broken.
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
# ENCRYPTION CONFIG  (keep in sync with client_proxy.py)
# ─────────────────────────────────────────────
WIRE_SHIFT = 7   # client encrypts with +7 → server decrypts with -7
DB_SHIFT   = 13  # server encrypts DB fields with +13; decrypts on read with -13

def _caesar(text: str, shift: int) -> str:
    """
    Shift every printable ASCII character (0x20–0x7E) by `shift` positions
    (wraps within that range).  All other characters (newlines, unicode, …)
    are passed through unchanged so protocol framing is never affected.
    """
    result = []
    RANGE = 95          # 0x7E - 0x20 + 1  (the 95 printable ASCII chars)
    shift = shift % RANGE
    for ch in text:
        code = ord(ch)
        if 0x20 <= code <= 0x7E:
            result.append(chr(0x20 + (code - 0x20 + shift) % RANGE))
        else:
            result.append(ch)
    return "".join(result)

def wire_decrypt(text: str) -> str:
    """Undo the client's WIRE_SHIFT encryption."""
    return _caesar(text, -WIRE_SHIFT)

def db_encrypt(text: str) -> str:
    """Encrypt a string before writing it to MySQL."""
    return _caesar(text, DB_SHIFT)

def db_decrypt(text: str) -> str:
    """Decrypt a string after reading it from MySQL."""
    return _caesar(text, -DB_SHIFT)

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
    "password": "67",
    "database": "email_server"
}

# ─────────────────────────────────────────────
# DB HELPERS
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
# DATABASE INIT
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
            message     TEXT,
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
# SMTP SERVER
# ─────────────────────────────────────────────

def handle_smtp_client(conn, addr):
    print(f"[SMTP] Connection from {addr}")
    def send(msg):
        conn.sendall((msg + "\r\n").encode())

    send("220 mailserver SMTP Ready")
    print("[SMTP] Sent 220")

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

                print("[SMTP RAW RECEIVED]", repr(line))

                if state["in_data"]:
                    if line.strip() == ".":
                        state["in_data"] = False
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
                                    # decrypt the wire-encrypted subject header
                                    subject = wire_decrypt(dl[8:].strip())
                                elif dl.lower().startswith("x-priority:"):
                                    p = dl.split(":", 1)[1].strip().lower()
                                    if p in ("low", "high", "normal"):
                                        priority = p
                            else:
                                body_lines.append(dl)

                        # Decrypt the wire-encrypted body
                        raw_body  = "\n".join(body_lines)
                        body      = wire_decrypt(raw_body)

                        # Decrypt envelope addresses (encrypted by client)
                        sender    = wire_decrypt(state["mail_from"])
                        rcpt_list = [wire_decrypt(r) for r in state["rcpt_to"]]

                        print(f"[SMTP] Decrypted — from: {sender}, subject: {subject}")

                        for rcpt in rcpt_list:
                            user = db_query(
                                "SELECT id FROM users WHERE email=%s",
                                (db_encrypt(rcpt),), fetchone=True
                            )
                            if user:
                                # Re-encrypt for DB storage using DB_SHIFT
                                db_query(
                                    """INSERT INTO emails
                                       (sender, recipient, subject, message, priority, received_at)
                                       VALUES (%s, %s, %s, %s, %s, NOW())""",
                                    (
                                        db_encrypt(sender),
                                        db_encrypt(rcpt),
                                        db_encrypt(subject),
                                        db_encrypt(body),
                                        priority,          # priority is not sensitive
                                    ),
                                    commit=True
                                )
                                print(f"[SMTP] Stored (DB-encrypted) → {rcpt}")
                            else:
                                print(f"[SMTP] Unknown recipient {rcpt}, discarding")

                        send("250 OK: message queued")
                        state["mail_from"]  = None
                        state["rcpt_to"]    = []
                        state["data_lines"] = []
                    else:
                        state["data_lines"].append(line[1:] if line.startswith("..") else line)
                    continue

                cmd = line.strip().upper()

                if cmd in ("HELO", "") or cmd.startswith("HELO ") or cmd.startswith("EHLO "):
                    state["helo_done"] = True
                    domain = line.strip().split(None, 1)[1] if " " in line.strip() else "unknown"
                    send(f"250 Hello {domain}, pleased to meet you")

                elif cmd.startswith("MAIL FROM"):
                    if not state["helo_done"]:
                        send("503 Bad sequence: send HELO first")
                        continue
                    m = re.search(r"<(.+?)>", line) or re.search(r"FROM:\s*(\S+)", line, re.I)
                    if m:
                        # Store the raw (wire-encrypted) address; decrypt later in DATA
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
# POP3 SERVER
# ─────────────────────────────────────────────

def handle_pop3_client(conn, addr):
    print(f"[POP3] Connection from {addr}")
    def send(msg):
        conn.sendall((msg + "\r\n").encode())

    send("+OK POP3 server ready")

    state      = "AUTHORIZATION"
    user_email = None
    session_emails = []
    deleted    = set()

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
                cmd = cmd_parts[0].upper()
                arg = cmd_parts[1] if len(cmd_parts) > 1 else ""

                if state == "AUTHORIZATION":
                    if cmd == "USER":
                        # arg arrives plaintext from client (login credentials are not encrypted)
                        decrypted_email = wire_decrypt(arg)

                        user = db_query(
                            "SELECT id FROM users WHERE email=%s",
                            (db_encrypt(decrypted_email),),
                            fetchone=True
                        )

                        if user:
                            user_email = decrypted_email
                            send(f"+OK {decrypted_email} found")
                        else:
                            send("-ERR no such user")


                    elif cmd == "PASS":

                        if not user_email:
                            send("-ERR send USER first")

                            continue

                        # decrypt wire

                        decrypted_password = wire_decrypt(arg)

                        # encrypt like DB

                        enc_password = db_encrypt(decrypted_password)

                        user = db_query(

                            "SELECT id FROM users WHERE email=%s AND password=%s",

                            (db_encrypt(user_email), enc_password),

                            fetchone=True

                        )

                        if user:

                            session_emails = db_query(

                                """SELECT id, sender, recipient, subject, message,

                                          priority, is_read, received_at

                                   FROM emails

                                   WHERE recipient=%s AND is_deleted=0

                                   ORDER BY received_at DESC""",

                                (db_encrypt(user_email),),

                                fetchall=True

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

                elif state == "TRANSACTION":
                    if cmd == "STAT":
                        active     = [e for i, e in enumerate(session_emails, 1) if i not in deleted]
                        total_size = sum(len((e.get("message") or "").encode()) for e in active)
                        send(f"+OK {len(active)} {total_size}")

                    elif cmd == "LIST":
                        if arg:
                            try:
                                idx = int(arg)
                                if 1 <= idx <= len(session_emails) and idx not in deleted:
                                    size = len((session_emails[idx - 1].get("message") or "").encode())
                                    send(f"+OK {idx} {size}")
                                else:
                                    send("-ERR no such message")
                            except ValueError:
                                send("-ERR invalid argument")
                        else:
                            active = [(i + 1, e) for i, e in enumerate(session_emails) if (i + 1) not in deleted]
                            send(f"+OK {len(active)} messages")
                            for idx, e in active:
                                size = len((e.get("message") or "").encode())
                                send(f"{idx} {size}")
                            send(".")

                    elif cmd == "RETR":
                        try:
                            idx = int(arg)
                            if 1 <= idx <= len(session_emails) and idx not in deleted:
                                e = session_emails[idx - 1]

                                # Decrypt DB fields before sending back over the wire.
                                # The client will then apply a second wire_decrypt pass,
                                # so we must re-apply wire_encrypt here so the client
                                # ends up with plaintext.
                                raw_sender  = db_decrypt(e.get("sender", ""))
                                raw_rcpt    = db_decrypt(e.get("recipient", ""))
                                raw_subject = db_decrypt(e.get("subject", ""))
                                raw_body    = db_decrypt(e.get("message", "") or "")

                                # Re-encrypt with WIRE_SHIFT so the client proxy can decrypt
                                wire_sender  = _caesar(raw_sender,  WIRE_SHIFT)
                                wire_rcpt    = _caesar(raw_rcpt,    WIRE_SHIFT)
                                wire_subject = _caesar(raw_subject, WIRE_SHIFT)
                                wire_body    = _caesar(raw_body,    WIRE_SHIFT)

                                size = len(wire_body.encode())
                                send(f"+OK {size} octets")
                                send(f"From: {wire_sender}")
                                send(f"To: {wire_rcpt}")
                                send(f"Subject: {wire_subject}")
                                send(f"X-Priority: {e.get('priority', 'normal')}")
                                recv_at = e.get("received_at")
                                send(f"Date: {recv_at}")
                                send("")  # blank line = body starts

                                for bl in wire_body.split("\n"):
                                    send(("." + bl) if bl.startswith(".") else bl)
                                send(".")

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
                        for idx in deleted:
                            eid = session_emails[idx - 1]["id"]
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
# FASTAPI  (signup / login — credentials NOT encrypted)
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
    # Step 1: decrypt incoming wire data
    email = wire_decrypt(data.email)
    password = wire_decrypt(data.password)

    # Step 2: encrypt for DB storage
    enc_email = db_encrypt(email)
    enc_password = db_encrypt(password)

    # Step 3: check existing user
    existing = db_query(
        "SELECT id FROM users WHERE email=%s",
        (enc_email,),
        fetchone=True
    )

    if existing:
        raise HTTPException(status_code=400, detail="User already exists")

    # Step 4: store
    db_query(
        "INSERT INTO users (email, password) VALUES (%s, %s)",
        (enc_email, enc_password),
        commit=True
    )

    return {"message": "User created successfully"}

@app.post("/login")
def login(data: LoginRequest):
    # Step 1: decrypt wire
    email = wire_decrypt(data.email)
    password = wire_decrypt(data.password)

    # Step 2: encrypt same way as DB
    enc_email = db_encrypt(email)
    enc_password = db_encrypt(password)

    # Step 3: match directly
    user = db_query(
        "SELECT * FROM users WHERE email=%s AND password=%s",
        (enc_email, enc_password),
        fetchone=True
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