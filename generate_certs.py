"""
generate_certs.py  –  Generate self-signed TLS certificate (Windows-friendly)
Run:  python generate_certs.py
Produces: cert.pem  and  key.pem  in the current directory.
"""

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
import datetime
import ipaddress

print("[TLS] Generating RSA-2048 private key...")
key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)

# Write private key
with open("key.pem", "wb") as f:
    f.write(key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    ))
print("[TLS] key.pem written.")

# Build certificate
subject = issuer = x509.Name([
    x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
    x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Local"),
    x509.NameAttribute(NameOID.LOCALITY_NAME, "Dev"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SecureMessaging"),
    x509.NameAttribute(NameOID.COMMON_NAME, "127.0.0.1"),
])

cert = (
    x509.CertificateBuilder()
    .subject_name(subject)
    .issuer_name(issuer)
    .public_key(key.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(datetime.datetime.utcnow())
    .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
    .add_extension(
        x509.SubjectAlternativeName([
            x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
            x509.DNSName("localhost"),
        ]),
        critical=False,
    )
    .sign(key, hashes.SHA256(), default_backend())
)

with open("cert.pem", "wb") as f:
    f.write(cert.public_bytes(serialization.Encoding.PEM))
print("[TLS] cert.pem written.")

print("\n[TLS] Done! Both cert.pem and key.pem are ready.")
print("[TLS] Run:  python server.py   to start the HTTPS server.")
