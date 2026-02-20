import sys
from pathlib import Path

sys.path.append(str(Path(__file__).parent.parent))
from services.certificate_generator import certificate_generator

def main():
    """Initialize CA and create directories"""
    print("🔐 Initializing V2V Certificate Authority...")
    
    print(f"✅ CA Certificate: {certificate_generator.ca_cert_path}")
    print(f"✅ CA Key: {certificate_generator.ca_key_path}")
    print(f"✅ CA Subject: {certificate_generator.ca_cert.subject}")
    print(f"✅ CA Valid until: {certificate_generator.ca_cert.not_valid_after_utc}")
    
    print("\n📁 Certificate directories:")
    print(f"   - Certificates: {certificate_generator.certs_dir}")
    print(f"   - Private keys: {certificate_generator.private_keys_dir}")
    print(f"   - Public keys: {certificate_generator.public_keys_dir}")
    
    print("\n🚀 CA initialization complete!")

if __name__ == "__main__":
    main()