"""
client_proxy.py — Run this on client
Exposes a local REST API on port 9000 that the browser talks to.
Internally speaks raw SMTP (port 2525) and POP3 (port 1100) to the server.

Offline queue: if the SMTP server is unreachable, emails are saved to
queue.json and retried every 30 seconds automatically.

Requirements: pip install fastapi uvicorn 
Run: python client_proxy.py

Encryption notes
────────────────
  WIRE_SHIFT — Caesar shift applied here before any data is sent over the
               raw TCP sockets (SMTP or POP3).  On receive (POP3 RETR) the
               server has already re-encrypted the stored data with this
               same shift, so we decrypt here to give the browser plaintext.

  Only printable ASCII (0x20–0x7E) is shifted.  CRLF, protocol dots, and
  non-ASCII bytes are left alone so SMTP/POP3 framing is never corrupted.

  Must match WIRE_SHIFT in server.py.
"""

import socket
import threading
import time
import json
import os
import uvicorn
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional
import httpx

# ─────────────────────────────────────────────
# ENCRYPTION CONFIG  (keep in sync with server.py)
# ─────────────────────────────────────────────
WIRE_SHIFT = 7   # must match server.py

def _caesar(text: str, shift: int) -> str:
    """
    Shift every printable ASCII character (0x20–0x7E) by `shift` positions
    (wraps within that 95-character range).  All other bytes pass through
    unchanged so CRLF and protocol dots are never disturbed.
    """
    result = []
    RANGE  = 95        # 0x7E - 0x20 + 1
    shift  = shift % RANGE
    for ch in text:
        code = ord(ch)
        if 0x20 <= code <= 0x7E:
            result.append(chr(0x20 + (code - 0x20 + shift) % RANGE))
        else:
            result.append(ch)
    return "".join(result)

def wire_encrypt(text: str) -> str:
    """Encrypt a string before sending it over the raw TCP socket."""
    return _caesar(text, WIRE_SHIFT)

def wire_decrypt(text: str) -> str:
    """Decrypt a string received from the server over the raw TCP socket."""
    return _caesar(text, -WIRE_SHIFT)

SERVER_IP   = "172.18.15.11"   
SMTP_PORT   = 2525
POP3_PORT   = 1100
API_PORT    = 8000
PROXY_PORT  = 9000

QUEUE_FILE  = "queue.json"
RETRY_EVERY = 30

# ─────────────────────────────────────────────
# OFFLINE QUEUE
# ─────────────────────────────────────────────

queue_lock = threading.Lock()

def load_queue():
    if os.path.exists(QUEUE_FILE):
        try:
            with open(QUEUE_FILE) as f:
                return json.load(f)
        except Exception:
            return []
    return []

def save_queue(q):
    with open(QUEUE_FILE, "w") as f:
        json.dump(q, f, indent=2)

def enqueue(email_dict):
    with queue_lock:
        q = load_queue()
        q.append(email_dict)
        save_queue(q)
    print(f"[QUEUE] Queued email to {email_dict['recipient']} (queue size: {len(load_queue())})")

def dequeue_all():
    with queue_lock:
        q = load_queue()
        save_queue([])
    return q

def requeue_failed(failed_list):
    with queue_lock:
        q = load_queue()
        q = failed_list + q
        save_queue(q)

# ─────────────────────────────────────────────
# RAW SMTP CLIENT  (encrypts payload before sending)
# ─────────────────────────────────────────────

class SMTPError(Exception):
    pass

def smtp_send(sender: str, recipient: str, subject: str,
              body: str, priority: str = "normal") -> bool:
    """
    Opens a raw TCP connection to the SMTP server and sends one email.

    The envelope addresses (MAIL FROM / RCPT TO) and the DATA section
    (headers + body) are Caesar-encrypted with WIRE_SHIFT before going
    onto the wire.  A Wireshark capture will show only shifted characters.

    Returns True on success, raises SMTPError on failure.
    """
    def readline(sock):
        buf = b""
        while True:
            c = sock.recv(1)
            if not c:
                raise SMTPError("Connection closed by server")
            buf += c
            if buf.endswith(b"\r\n") or buf.endswith(b"\n"):
                return buf.decode(errors="replace").strip()

    def expect(sock, code):
        line = readline(sock)
        print(f"  [SMTP<] {line}")
        if not line.startswith(str(code)):
            raise SMTPError(f"Expected {code}, got: {line}")
        return line

    def sendline(sock, msg):
        print(f"  [SMTP>] {msg}")
        sock.sendall((msg + "\r\n").encode())

    # Encrypt the sensitive fields
    enc_sender    = wire_encrypt(sender)
    enc_recipient = wire_encrypt(recipient)
    enc_subject   = wire_encrypt(subject)
    enc_body      = wire_encrypt(body)

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        sock.connect((SERVER_IP, SMTP_PORT))

        expect(sock, 220)
        sendline(sock, "HELO client")
        expect(sock, 250)

        # Encrypted envelope addresses
        sendline(sock, f"MAIL FROM:<{enc_sender}>")
        expect(sock, 250)

        sendline(sock, f"RCPT TO:<{enc_recipient}>")
        expect(sock, 250)

        sendline(sock, "DATA")
        expect(sock, 354)

        # Encrypted headers
        sendline(sock, f"From: {enc_sender}")
        sendline(sock, f"To: {enc_recipient}")
        sendline(sock, f"Subject: {enc_subject}")
        sendline(sock, f"X-Priority: {priority}")   # priority is not sensitive
        sendline(sock, "")                           # blank line → body

        # Encrypted body (dot-stuffing still applied to the encrypted text)
        for line in enc_body.split("\n"):
            sendline(sock, ("." + line) if line.startswith(".") else line)

        sendline(sock, ".")
        expect(sock, 250)

        sendline(sock, "QUIT")
        expect(sock, 221)

        sock.close()
        return True

    except (socket.timeout, ConnectionRefusedError, OSError) as e:
        raise SMTPError(f"Network error: {e}")


# ─────────────────────────────────────────────
# RAW POP3 CLIENT  (decrypts payload after receiving)
# ─────────────────────────────────────────────

class POP3Error(Exception):
    pass

def pop3_get_inbox(email: str, password: str) -> list:
    def readline(sock):
        buf = b""
        while True:
            c = sock.recv(1)
            if not c:
                raise POP3Error("Connection closed")
            buf += c
            if buf.endswith(b"\r\n") or buf.endswith(b"\n"):
                return buf.decode(errors="replace").strip()

    def expect_ok(sock):
        line = readline(sock)
        print(f"  [POP3<] {line}")
        if not line.startswith("+OK"):
            raise POP3Error(f"Server said: {line}")
        return line

    def sendline(sock, msg):
        print(f"  [POP3>] {msg}")
        sock.sendall((msg + "\r\n").encode())

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(15)
        sock.connect((SERVER_IP, POP3_PORT))

        expect_ok(sock)

        sendline(sock, f"USER {wire_encrypt(email)}")
        expect_ok(sock)

        # already correct
        sendline(sock, f"PASS {wire_encrypt(password)}")
        expect_ok(sock)

        sendline(sock, "STAT")
        stat   = expect_ok(sock)
        parts  = stat.split()
        count  = int(parts[1]) if len(parts) >= 2 else 0

        emails = []
        for i in range(1, count + 1):
            sendline(sock, f"RETR {i}")
            expect_ok(sock)

            headers    = {}
            body_lines = []
            in_body    = False

            while True:
                line = readline(sock)
                if line == ".":
                    break
                if in_body:
                    body_lines.append(line)
                elif line == "":
                    in_body = True
                else:
                    if ":" in line:
                        k, v = line.split(":", 1)
                        headers[k.strip().lower()] = v.strip()

            emails.append({
                "sender":    wire_decrypt(headers.get("from", "")),
                "recipient": wire_decrypt(headers.get("to", "")),
                "subject":   wire_decrypt(headers.get("subject", "")),
                "priority":  headers.get("x-priority", "normal"),
                "date":      headers.get("date", ""),
                "body":      wire_decrypt("\n".join(body_lines)),
            })

        sendline(sock, "QUIT")
        try:
            expect_ok(sock)
        except Exception:
            pass

        sock.close()
        return emails

    except (socket.timeout, ConnectionRefusedError, OSError) as e:
        raise POP3Error(f"Network error: {e}")

# ─────────────────────────────────────────────
# QUEUE RETRY WORKER
# ─────────────────────────────────────────────

def queue_worker():
    while True:
        time.sleep(RETRY_EVERY)
        pending = load_queue()
        if not pending:
            continue
        print(f"[QUEUE] Retrying {len(pending)} queued email(s)…")
        failed = []
        dequeue_all()
        for email in pending:
            try:
                smtp_send(
                    email["sender"], email["recipient"],
                    email["subject"], email["body"], email["priority"]
                )
                print(f"[QUEUE] ✓ Delivered queued email to {email['recipient']}")
            except SMTPError as e:
                print(f"[QUEUE] ✗ Still offline: {e}")
                failed.append(email)
        if failed:
            requeue_failed(failed)
            print(f"[QUEUE] {len(failed)} email(s) re-queued for next retry")


# ─────────────────────────────────────────────
# PROXY REST API  (browser ↔ proxy)
# ─────────────────────────────────────────────

proxy = FastAPI()
proxy.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class SignupReq(BaseModel):
    email: str
    password: str

class LoginReq(BaseModel):
    email: str
    password: str

class SendReq(BaseModel):
    sender: str
    password: str
    recipient: str
    subject: str = ""
    body: str = ""
    priority: str = "normal"

class InboxReq(BaseModel):
    email: str
    password: str


async def forward_to_api(path: str, payload: dict):
    url = f"http://{SERVER_IP}:{API_PORT}{path}"
    async with httpx.AsyncClient(timeout=8) as client:
        resp = await client.post(url, json=payload)
    return resp
@proxy.post("/signup")
async def proxy_signup(data: SignupReq):
    try:
        payload = {
            "email": wire_encrypt(data.email),
            "password": wire_encrypt(data.password)
        }

        resp = await forward_to_api("/signup", payload)

        if resp.status_code != 200:
            raise HTTPException(status_code=resp.status_code, detail=resp.json().get("detail", "Error"))

        return resp.json()

    except httpx.ConnectError:
        raise HTTPException(status_code=503, detail="Server unreachable")

@proxy.post("/login")
async def proxy_login(data: LoginReq):
    try:
        payload = {
            "email": wire_encrypt(data.email),
            "password": wire_encrypt(data.password)
        }

        resp = await forward_to_api("/login", payload)

        if resp.status_code != 200:
            raise HTTPException(status_code=resp.status_code, detail=resp.json().get("detail", "Error"))

        return resp.json()

    except httpx.ConnectError:
        raise HTTPException(status_code=503, detail="Server unreachable")

@proxy.post("/send")
async def proxy_send(data: SendReq):
    email_dict = {
        "sender":    data.sender,
        "recipient": data.recipient,
        "subject":   data.subject,
        "body":      data.body,
        "priority":  data.priority,
    }
    try:
        smtp_send(data.sender, data.recipient, data.subject, data.body, data.priority)
        return {"message": "Email sent", "queued": False}
    except SMTPError as e:
        enqueue(email_dict)
        return {"message": f"Server offline — email queued for retry (reason: {e})", "queued": True}

@proxy.post("/inbox")
async def proxy_inbox(data: InboxReq):
    try:
        emails = pop3_get_inbox(data.email, data.password)
        return {"count": len(emails), "emails": emails}
    except POP3Error as e:
        raise HTTPException(status_code=503, detail=f"POP3 error: {e}")

@proxy.get("/queue_status")
def queue_status():
    q = load_queue()
    return {"queued": len(q), "emails": q}

@proxy.get("/health")
def health():
    try:
        s = socket.create_connection((SERVER_IP, SMTP_PORT), timeout=3)
        s.close()
        return {"server": "online"}
    except Exception:
        return {"server": "offline"}


if __name__ == "__main__":
    print(f"[PROXY] Client proxy starting on port {PROXY_PORT}")
    print(f"[PROXY] Targeting server at {SERVER_IP}")
    print(f"[PROXY] Wire encryption: Caesar shift +{WIRE_SHIFT}")
    threading.Thread(target=queue_worker, daemon=True).start()
    uvicorn.run(proxy, host="0.0.0.0", port=PROXY_PORT)
