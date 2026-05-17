# MailDrop Email Server

## Overview

This project is a small custom email system built from scratch using raw SMTP and POP3 protocols, plus a browser-friendly REST proxy for the client side.

It has three main parts:

1. `server.py`

   - Runs an SMTP server on port `2525`
   - Runs a POP3 server on port `1100`
   - Runs a FastAPI auth API on port `8000`
   - Stores users and messages in a MySQL database

2. `client_proxy.py`

   - Runs a local proxy on port `9000`
   - The browser talks to this proxy over HTTP
   - The proxy translates browser requests into raw SMTP and POP3 commands
   - It also provides offline queuing when the SMTP server is unreachable

3. `index.html`
   - A browser-based UI for signup, login, composing email, and reading inbox messages
   - Talks only to the local proxy at `http://localhost:9000`

---

## How it works

### `server.py`

- **Database**

  - Uses MySQL with `email_server` database
  - Creates `users` and `emails` tables automatically on startup
  - `users` holds `email` and `password`
  - `emails` holds sender, recipient, subject, message body, priority, read/delete flags, and timestamp

- **SMTP server**

  - Implements a minimal SMTP handshake: `HELO` / `EHLO`, `MAIL FROM`, `RCPT TO`, `DATA`, `QUIT`, `RSET`, `NOOP`
  - Accepts email data and stores it in the `emails` table for each valid recipient
  - Supports basic headers: `Subject`, `X-Priority`
  - Uses dot-stuffing correctly
  - Validates recipient existence before saving messages

- **POP3 server**

  - Implements a minimal POP3 flow: `USER`, `PASS`, `STAT`, `LIST`, `RETR`, `DELE`, `RSET`, `NOOP`, `QUIT`
  - Authenticates users against the `users` table
  - Loads inbox messages for the recipient and serves them in session
  - Marks retrieved messages as read and supports deletion on `QUIT`

- **FastAPI auth API**
  - Exposes `/signup` and `/login` endpoints
  - Used by the browser proxy for user authentication
  - Expects encrypted credentials from the proxy

### `client_proxy.py`

- **Local REST API**

  - Listens on `http://localhost:9000`
  - Exposes endpoints:
    - `POST /signup` → forwards to server FastAPI `/signup`
    - `POST /login` → forwards to server FastAPI `/login`
    - `POST /send` → sends email over raw SMTP
    - `POST /inbox` → reads inbox over raw POP3
    - `GET /queue_status` → returns queued outgoing emails
    - `GET /health` → checks SMTP server availability

- **Raw SMTP client**

  - Opens a TCP socket to the server's SMTP port
  - Sends SMTP commands directly and reads responses
  - Encrypts all printable text fields using a Caesar shift before writing to the network
  - If sending fails, saves the mail to `queue.json`

- **Raw POP3 client**

  - Opens a TCP socket to the server's POP3 port
  - Sends POP3 commands directly and reads responses
  - Encrypts `USER` and `PASS` values before sending
  - Decrypts `From`, `To`, `Subject`, and body text after receiving

- **Offline queue**

  - If SMTP is unavailable, outgoing messages are saved to `queue.json`
  - A background worker retries queued emails every `30` seconds
  - If retry fails again, the message remains queued

- **Encryption**
  - Uses a simple Caesar cipher with shift `7`
  - Only shifts printable ASCII characters (`0x20` to `0x7E`)
  - Keeps protocol framing characters such as CRLF intact
  - Must use the same `WIRE_SHIFT` in both `server.py` and `client_proxy.py`
  - Note: this is not strong encryption; it is only an obfuscation layer over raw TCP

### `index.html`

- Browser UI for the email client
- Provides:
  - Signup and login screens
  - Compose message pane
  - Inbox listing and message detail view
- Uses the local proxy at `http://localhost:9000`
- Does not talk directly to SMTP or POP3
- Maintains the current signed-in user and password in memory only

---

## Setup & run

### Server machine

1. Install dependencies:
   - `pip install fastapi uvicorn mysql-connector-python`
2. Ensure MySQL is running and accessible with the credentials in `server.py`
3. Run the server:
   - `python server.py`
4. Server listens on:
   - SMTP: `0.0.0.0:2525`
   - POP3: `0.0.0.0:1100`
   - API: `0.0.0.0:8000`

### Client machine

1. Install dependencies:
   - `pip install fastapi uvicorn httpx`
2. Open `client_proxy.py` and replace `SERVER_IP` with the server machine's LAN IP
3. Run the client proxy:
   - `python client_proxy.py`
4. Proxy listens on:
   - `http://localhost:9000`

### Browser

- Open `index.html` in your browser
- Use the signup/login form, then compose email or read inbox
- The browser communicates only with the local proxy

---

## Important notes

- This system is a learning/demo project, not production-grade mail software.
- Passwords are stored in plaintext in MySQL.
- The Caesar shift is not secure; it is only used to hide raw SMTP/POP3 wire contents from casual inspection.
- The proxy and server rely on fixed ports and plaintext protocol handling.
- If the SMTP server is down, outgoing emails are saved to `queue.json` and retried automatically.
