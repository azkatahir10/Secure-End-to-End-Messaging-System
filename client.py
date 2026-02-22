"""
Secure End-to-End Messaging Client
====================================
Security features implemented:
- RSA-2048 key pair generation per user (private key stored locally only)
- Hybrid encryption: AES-256-GCM for message + RSA-OAEP for key exchange
- Client-side private key ownership (server NEVER sees private key)
- TLS certificate verification (HTTPS only)
- Session token stored in memory only (not on disk)
- Server cannot decrypt messages — only the recipient's private key can
"""

import os
import base64
import getpass
import json

import requests
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.asymmetric.padding import OAEP, MGF1
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# ─── Configuration ───────────────────────────────────────────────────────────
SERVER = "https://127.0.0.1:5443"
# Path to the server's self-signed CA cert for TLS verification
# Set to False ONLY during local dev; True in production
CA_CERT = "cert.pem"   # verify=CA_CERT tells requests to trust this cert
VERIFY  = CA_CERT       # Change to True for Let's Encrypt / real CA

# In-memory state (never persisted to disk during session)
session_token: str | None = None
my_private_key = None
my_username: str | None = None


# ─── RSA Key Management ──────────────────────────────────────────────────────

def generate_rsa_keypair(username: str):
    """
    Generate a 2048-bit RSA key pair.
    Private key is saved locally (protected by passphrase).
    Public key is uploaded to the server's public key registry.
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    # Serialize private key with AES-256-CBC passphrase protection
    passphrase = getpass.getpass(f"[KEY] Enter passphrase to protect your private key: ").encode()
    pem_private = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(passphrase),
    )
    key_file = f"{username}_private.pem"
    with open(key_file, "wb") as f:
        f.write(pem_private)
    print(f"[KEY] Private key saved to: {key_file}  (KEEP THIS SECRET)")

    # Public key in PEM format – safe to share with the server
    pem_public = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()

    return private_key, pem_public


def load_private_key(username: str):
    """Load and decrypt private key from disk."""
    key_file = f"{username}_private.pem"
    if not os.path.exists(key_file):
        print(f"[ERROR] Private key file not found: {key_file}")
        return None
    passphrase = getpass.getpass("[KEY] Enter your private key passphrase: ").encode()
    with open(key_file, "rb") as f:
        try:
            private_key = serialization.load_pem_private_key(f.read(), password=passphrase)
            print("[KEY] Private key loaded successfully.")
            return private_key
        except Exception as e:
            print(f"[ERROR] Failed to load private key: {e}")
            return None


# ─── Cryptographic Primitives ────────────────────────────────────────────────

def encrypt_aes_gcm(plaintext: bytes, aes_key: bytes) -> tuple[bytes, bytes, bytes]:
    """
    AES-256-GCM authenticated encryption.
    Returns (ciphertext, nonce, tag).
    Note: cryptography's AESGCM returns ciphertext||tag concatenated.
    """
    nonce = os.urandom(12)  # 96-bit nonce (GCM standard)
    aesgcm = AESGCM(aes_key)
    ct_with_tag = aesgcm.encrypt(nonce, plaintext, None)
    # Last 16 bytes are the GCM authentication tag
    ciphertext = ct_with_tag[:-16]
    tag = ct_with_tag[-16:]
    return ciphertext, nonce, tag


def decrypt_aes_gcm(ciphertext: bytes, nonce: bytes, tag: bytes, aes_key: bytes) -> bytes:
    """Decrypt and verify AES-256-GCM ciphertext."""
    aesgcm = AESGCM(aes_key)
    ct_with_tag = ciphertext + tag
    return aesgcm.decrypt(nonce, ct_with_tag, None)


def rsa_encrypt(aes_key: bytes, recipient_public_key_pem: str) -> bytes:
    """Encrypt AES key using recipient's RSA public key (OAEP-SHA256)."""
    pub_key = serialization.load_pem_public_key(recipient_public_key_pem.encode())
    encrypted = pub_key.encrypt(
        aes_key,
        OAEP(mgf=MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
    )
    return encrypted


def rsa_decrypt(encrypted_key: bytes, private_key) -> bytes:
    """Decrypt AES key using our RSA private key (OAEP-SHA256)."""
    return private_key.decrypt(
        encrypted_key,
        OAEP(mgf=MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
    )


# ─── API Helpers ─────────────────────────────────────────────────────────────

def auth_headers() -> dict:
    return {"Authorization": f"Bearer {session_token}"}


def b64enc(data: bytes) -> str:
    return base64.b64encode(data).decode()


def b64dec(s: str) -> bytes:
    return base64.b64decode(s)


# ─── Client Operations ───────────────────────────────────────────────────────

def register(username: str, password: str):
    global my_private_key, my_username
    print(f"[REGISTER] Generating RSA-2048 key pair for {username}...")
    private_key, public_key_pem = generate_rsa_keypair(username)

    payload = {
        "username": username,
        "password": password,
        "public_key": public_key_pem,
    }
    r = requests.post(f"{SERVER}/register", json=payload, verify=VERIFY)
    data = r.json()
    print("[REGISTER]", data)
    if r.status_code == 200:
        my_private_key = private_key
        my_username = username
        print(f"[REGISTER] Success! Your public key has been uploaded to the server registry.")
        print(f"[REGISTER] Your private key is ONLY on your machine. The server never sees it.")


def login(username: str, password: str):
    global session_token, my_private_key, my_username
    private_key = load_private_key(username)
    if not private_key:
        return

    payload = {"username": username, "password": password}
    r = requests.post(f"{SERVER}/login", json=payload, verify=VERIFY)
    data = r.json()
    if r.status_code == 200:
        session_token = data["session_token"]
        my_private_key = private_key
        my_username = username
        print(f"[LOGIN] Authenticated as {username}. Session token stored in memory.")
    else:
        print("[LOGIN] Failed:", data)


def logout():
    global session_token
    r = requests.post(f"{SERVER}/logout", headers=auth_headers(), verify=VERIFY)
    print("[LOGOUT]", r.json())
    session_token = None


def send_message(recipient: str, plaintext: str):
    """
    Hybrid Encryption Flow:
    1. Generate random AES-256 key
    2. Encrypt message with AES-GCM → confidentiality + integrity
    3. Fetch recipient's RSA public key from server registry
    4. Encrypt AES key with RSA-OAEP → secure key exchange
    5. Send encrypted_key + ciphertext + nonce + tag to server
    Server stores ONLY ciphertext — it cannot decrypt anything.
    """
    if not session_token:
        print("[ERROR] Not logged in.")
        return

    # Step 1: Fetch recipient's public key from the PKI registry
    r = requests.get(f"{SERVER}/public_key/{recipient}", headers=auth_headers(), verify=VERIFY)
    if r.status_code != 200:
        print(f"[ERROR] Could not fetch public key for {recipient}:", r.json())
        return
    recipient_public_key_pem = r.json()["public_key"]
    print(f"[SEND] Fetched {recipient}'s public key from server registry.")

    # Step 2: Generate a fresh 256-bit AES key (per-message key)
    aes_key = os.urandom(32)   # AES-256

    # Step 3: Encrypt the plaintext message using AES-256-GCM
    ciphertext, nonce, tag = encrypt_aes_gcm(plaintext.encode(), aes_key)
    print(f"[SEND] Message encrypted with AES-256-GCM.")

    # Step 4: Encrypt the AES key with the recipient's RSA public key
    encrypted_key = rsa_encrypt(aes_key, recipient_public_key_pem)
    print(f"[SEND] AES key encrypted with RSA-OAEP (recipient's public key).")

    # Step 5: Send everything (all encrypted – server sees no plaintext)
    payload = {
        "to": recipient,
        "encrypted_key": b64enc(encrypted_key),
        "ciphertext":    b64enc(ciphertext),
        "nonce":         b64enc(nonce),
        "tag":           b64enc(tag),
    }
    r = requests.post(f"{SERVER}/send", json=payload, headers=auth_headers(), verify=VERIFY)
    print("[SEND]", r.json())


def fetch_and_decrypt_messages():
    """
    Decryption Flow (receiver side):
    1. Fetch encrypted messages from server (only our own – ACL enforced)
    2. Decrypt AES key using our RSA private key
    3. Decrypt message using AES-GCM (also verifies integrity via auth tag)
    4. Display plaintext to user
    """
    if not session_token:
        print("[ERROR] Not logged in.")
        return
    if not my_private_key:
        print("[ERROR] Private key not loaded.")
        return

    r = requests.get(f"{SERVER}/messages", headers=auth_headers(), verify=VERIFY)
    if r.status_code != 200:
        print("[ERROR]", r.json())
        return

    inbox = r.json()
    if not inbox:
        print("[INBOX] No messages.")
        return

    print(f"\n[INBOX] {len(inbox)} message(s):\n" + "="*50)
    for msg in inbox:
        try:
            # Step 1: Decode base64 fields
            enc_key   = b64dec(msg["encrypted_key"])
            ciphertext= b64dec(msg["ciphertext"])
            nonce     = b64dec(msg["nonce"])
            tag       = b64dec(msg["tag"])

            # Step 2: Decrypt the AES key using OUR private key
            aes_key = rsa_decrypt(enc_key, my_private_key)

            # Step 3: Decrypt message using AES-GCM (also verifies integrity)
            plaintext = decrypt_aes_gcm(ciphertext, nonce, tag, aes_key).decode()

            print(f"From:    {msg['sender']}")
            print(f"Message: {plaintext}")
            print("-"*50)
        except Exception as e:
            print(f"[ERROR] Failed to decrypt message from {msg.get('sender')}: {e}")

    print()


def demo_authz_failure(target_user: str):
    """Demonstrate that accessing another user's inbox returns 403."""
    r = requests.get(
        f"{SERVER}/messages/{target_user}",
        headers=auth_headers(),
        verify=VERIFY
    )
    print(f"\n[AUTHZ TEST] Trying to access {target_user}'s inbox as {my_username}:")
    print(f"  HTTP {r.status_code}: {r.json()}")


# ─── Main CLI ─────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("╔══════════════════════════════════════════╗")
    print("║   Secure E2E Messaging Client (TLS/E2E)  ║")
    print("╚══════════════════════════════════════════╝\n")

    while True:
        cmd = input("Command (register|login|logout|send|inbox|authz_test|quit): ").strip()

        if cmd == "register":
            u = input("Username: ").strip()
            p = getpass.getpass("Password: ")
            register(u, p)

        elif cmd == "login":
            u = input("Username: ").strip()
            p = getpass.getpass("Password: ")
            login(u, p)

        elif cmd == "logout":
            logout()

        elif cmd == "send":
            to  = input("To (username): ").strip()
            msg = input("Message: ").strip()
            send_message(to, msg)

        elif cmd == "inbox":
            fetch_and_decrypt_messages()

        elif cmd == "authz_test":
            target = input("Try to access inbox of user: ").strip()
            demo_authz_failure(target)

        elif cmd == "quit":
            if session_token:
                logout()
            print("Goodbye.")
            break

        else:
            print("Unknown command.")
