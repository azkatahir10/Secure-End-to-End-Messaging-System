# Secure End-to-End Messaging System
## Setup & Demo Instructions

---

## Prerequisites

```bash
pip install cryptography flask requests
```

---

## Step 1: Generate TLS Certificates

```bash
bash setup_tls.sh
```

This creates `cert.pem` (certificate) and `key.pem` (private key) in the current directory.

---

## Step 2: Start the Server

```bash
python server.py
```

You should see:
```
[SERVER] Starting secure HTTPS server on https://127.0.0.1:5443
```

---

## Step 3: Run Two Client Instances

**Terminal 2 – Alice:**
```
python client.py
Command: register
Username: alice
Password: (enter password)
[KEY] Enter passphrase to protect your private key: (choose a passphrase)
→ alice_private.pem is created locally
→ Alice's public key is uploaded to the server registry
```

**Terminal 3 – Bob:**
```
python client.py
Command: register
Username: bob
Password: (enter password)
[KEY] Enter passphrase to protect your private key: (choose a passphrase)
```

---

## Step 4: Login and Send a Message

**Alice logs in and sends to Bob:**
```
Command: login
Username: alice
Password: (enter password)
[KEY] Enter your private key passphrase: (enter passphrase)

Command: send
To: bob
Message: Hello Bob, this is a secret!
→ [SEND] Fetched bob's public key from server registry.
→ [SEND] Message encrypted with AES-256-GCM.
→ [SEND] AES key encrypted with RSA-OAEP (recipient's public key).
→ [SEND] {'status': 'message stored'}
```

---

## Step 5: Bob Reads and Decrypts

**Bob logs in and reads inbox:**
```
Command: login
Username: bob
...

Command: inbox
[INBOX] 1 message(s):
==================================================
From:    alice
Message: Hello Bob, this is a secret!
--------------------------------------------------
```

---

## Step 6: Demo Authorization Failure

**Alice tries to read Bob's inbox:**
```
Command: authz_test
Try to access inbox of user: bob
[AUTHZ TEST] Trying to access bob's inbox as alice:
  HTTP 403: {'error': "Forbidden – you can only read your own messages"}
```

---

## What to Screenshot for the Assignment

1. **Server terminal** — showing encrypted data in logs (no plaintext)
2. **Client terminal** — Alice sending a message (shows encryption steps)
3. **Client terminal** — Bob receiving and decrypting the message
4. **Authorization failure** — HTTP 403 when Alice tries to read Bob's inbox
5. **TLS** — HTTPS URL in the server startup message; or use `curl -v https://127.0.0.1:5443/` to show TLS handshake

---

## File Overview

| File | Purpose |
|------|---------|
| `server.py` | Flask HTTPS server with IAM, sessions, ACL, message storage |
| `client.py` | Client with RSA key generation, hybrid encryption, TLS |
| `setup_tls.sh` | OpenSSL script to generate self-signed certificate |
| `design_document.docx` | Security justification (Task 7) |

---

## Task Checklist

- [x] Task 1 – Code analysis (see Design Document Section 1)
- [x] Task 2 – Password hashing (PBKDF2), session tokens, login/logout
- [x] Task 3 – Hybrid encryption (AES-256-GCM + RSA-OAEP)
- [x] Task 4 – Message storage with ACL (`403` on unauthorized access)
- [x] Task 5 – Client-side decryption with RSA private key
- [x] Task 6 – HTTPS / TLS with `setup_tls.sh`
- [x] Task 7 – Design document with security justification
