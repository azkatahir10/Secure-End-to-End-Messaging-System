"""
Secure End-to-End Messaging Server
===================================
Security features implemented:
- Password hashing with PBKDF2-HMAC-SHA256 (bcrypt-equivalent strength)
- Secure session token generation (secrets.token_hex)
- Session storage (in-memory dictionary)
- Authorization checks (ACLs) – only recipient can fetch their messages
- Server-side public key registry (stores only public keys)
- HTTPS with TLS (self-signed certificate via OpenSSL)
- Server never sees or stores plaintext messages
- Plain HTTP rejected (server only binds to HTTPS)
"""

from flask import Flask, request, jsonify
import uuid
import os
import secrets
import hashlib
import base64
import sqlite3
import json

app = Flask(__name__)

# ─── In-memory stores ────────────────────────────────────────────────────────
# users[username] = {"password_hash": str, "salt": str, "public_key": str}
users = {}
# sessions[token] = username
sessions = {}
# messages list of dicts
messages = []


# ─── Password hashing (PBKDF2-HMAC-SHA256) ───────────────────────────────────
def hash_password(password: str) -> tuple[str, str]:
    """Returns (hash_hex, salt_hex). Uses 600,000 iterations per OWASP 2023."""
    salt = secrets.token_bytes(32)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 600_000)
    return dk.hex(), salt.hex()


def verify_password(password: str, stored_hash: str, stored_salt: str) -> bool:
    salt = bytes.fromhex(stored_salt)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 600_000)
    return secrets.compare_digest(dk.hex(), stored_hash)


# ─── Auth helper ─────────────────────────────────────────────────────────────
def get_session_user(req) -> str | None:
    token = req.headers.get("Authorization", "").replace("Bearer ", "")
    return sessions.get(token)


# ─── Routes ──────────────────────────────────────────────────────────────────

@app.route("/register", methods=["POST"])
def register():
    data = request.get_json()
    username = data.get("username", "").strip()
    password = data.get("password", "")
    public_key = data.get("public_key", "")

    if not username or not password or not public_key:
        return jsonify({"error": "username, password, and public_key are required"}), 400
    if username in users:
        return jsonify({"error": "User already exists"}), 400

    pw_hash, pw_salt = hash_password(password)
    users[username] = {
        "password_hash": pw_hash,
        "salt": pw_salt,
        "public_key": public_key,   # PEM string, base64-safe
    }
    app.logger.info(f"[REGISTER] New user registered: {username}")
    return jsonify({"status": "registered"}), 200


@app.route("/login", methods=["POST"])
def login():
    data = request.get_json()
    username = data.get("username", "")
    password = data.get("password", "")

    user = users.get(username)
    if not user or not verify_password(password, user["password_hash"], user["salt"]):
        return jsonify({"error": "Invalid credentials"}), 401

    # Secure session token: 32 bytes = 256-bit entropy
    token = secrets.token_hex(32)
    sessions[token] = username
    app.logger.info(f"[LOGIN] User logged in: {username}")
    return jsonify({"session_token": token}), 200


@app.route("/logout", methods=["POST"])
def logout():
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    username = sessions.pop(token, None)
    if username:
        app.logger.info(f"[LOGOUT] User logged out: {username}")
        return jsonify({"status": "logged out"}), 200
    return jsonify({"error": "Invalid session"}), 401


@app.route("/public_key/<username>", methods=["GET"])
def get_public_key(username):
    """
    Public Key Registry: any authenticated user can query another user's public key.
    This is the PKI trust anchor — clients use this to encrypt the AES key.
    """
    requesting_user = get_session_user(request)
    if not requesting_user:
        return jsonify({"error": "Unauthorized"}), 401

    user = users.get(username)
    if not user:
        return jsonify({"error": "User not found"}), 404

    return jsonify({"username": username, "public_key": user["public_key"]}), 200


@app.route("/send", methods=["POST"])
def send_message():
    sender = get_session_user(request)
    if not sender:
        return jsonify({"error": "Unauthorized"}), 401

    data = request.get_json()
    recipient = data.get("to", "")
    encrypted_key = data.get("encrypted_key")   # RSA-encrypted AES key (base64)
    ciphertext = data.get("ciphertext")          # AES-GCM ciphertext (base64)
    nonce = data.get("nonce")                    # AES-GCM nonce (base64)
    tag = data.get("tag")                        # AES-GCM auth tag (base64)

    if not all([recipient, encrypted_key, ciphertext, nonce, tag]):
        return jsonify({"error": "Missing required fields"}), 400
    if recipient not in users:
        return jsonify({"error": "Recipient not found"}), 404

    messages.append({
        "id": str(uuid.uuid4()),
        "sender": sender,
        "recipient": recipient,
        "encrypted_key": encrypted_key,
        "ciphertext": ciphertext,
        "nonce": nonce,
        "tag": tag,
    })
    # Server logs show ONLY encrypted data — no plaintext ever
    app.logger.info(
        f"[SEND] Message stored | from={sender} to={recipient} "
        f"ciphertext={ciphertext[:32]}... (truncated)"
    )
    return jsonify({"status": "message stored"}), 200


@app.route("/messages", methods=["GET"])
def fetch_messages():
    """
    ACL Enforcement: session user can only retrieve messages addressed to THEM.
    Attempting to fetch another user's messages returns 403.
    """
    user = get_session_user(request)
    if not user:
        return jsonify({"error": "Unauthorized"}), 401

    # ACL check built into the filter – server enforces recipient == session user
    user_messages = [m for m in messages if m["recipient"] == user]
    app.logger.info(f"[INBOX] {user} fetched {len(user_messages)} message(s)")
    return jsonify(user_messages), 200


# Demo route to show authorization failure
@app.route("/messages/<target_user>", methods=["GET"])
def fetch_other_messages(target_user):
    """Demonstrates 403 when a user tries to read someone else's inbox."""
    requester = get_session_user(request)
    if not requester:
        return jsonify({"error": "Unauthorized"}), 401
    if requester != target_user:
        app.logger.warning(
            f"[AUTHZ DENIED] {requester} tried to access {target_user}'s messages"
        )
        return jsonify({"error": "Forbidden – you can only read your own messages"}), 403
    user_messages = [m for m in messages if m["recipient"] == requester]
    return jsonify(user_messages), 200


if __name__ == "__main__":
    # ── TLS / HTTPS Setup ──────────────────────────────────────────────────
    # Requires cert.pem and key.pem generated by setup_tls.sh
    CERT = "cert.pem"
    KEY  = "key.pem"

    if not (os.path.exists(CERT) and os.path.exists(KEY)):
        print("[ERROR] TLS certificates not found!")
        print("Run:  bash setup_tls.sh   to generate self-signed certs.")
        exit(1)

    print("[SERVER] Starting secure HTTPS server on https://127.0.0.1:5443")
    print("[SERVER] Plain HTTP is NOT served. TLS only.")
    app.run(
        host="127.0.0.1",
        port=5443,
        ssl_context=(CERT, KEY),
        debug=False,        # Never True in production
    )
