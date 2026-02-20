# Add this to your test script or run in Python console
from pathlib import Path
from cryptography import x509
from cryptography.hazmat.backends import default_backend

ca_path = Path("/home/ezzudin/Documents/Projects/certs/ca/ca_cert.pem")
print(f"CA exists: {ca_path.exists()}")

if ca_path.exists():
    with open(ca_path, "rb") as f:
        ca_data = f.read()
    ca_cert = x509.load_pem_x509_certificate(ca_data, default_backend())
    print(f"CA Subject: {ca_cert.subject}")
    print(f"CA Valid until: {ca_cert.not_valid_after_utc}")