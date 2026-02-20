#!/usr/bin/env python3
"""
Test script to verify a certificate directly
"""

import sys
from pathlib import Path
from datetime import datetime, timezone

# Add parent directory to path
sys.path.append(str(Path(__file__).parent.parent))

try:
    from services.certificate_generator import certificate_generator
    from config.settings import settings
except ImportError as e:
    print(f"Import error: {e}")
    sys.exit(1)

def main():
    """Test certificate verification"""
    print("🔍 Testing Certificate Verification")
    print("=" * 50)
    
    # Path to your certificate
    cert_path = Path("/home/ezzudin/Documents/Projects/certs/vehicles/certs/ABC-test_20260220_065B072A.crt")
    
    print(f"Certificate path: {cert_path}")
    print(f"Path exists: {cert_path.exists()}")
    
    if not cert_path.exists():
        print("❌ Certificate file not found!")
        return
    
    # Read and display certificate info
    try:
        from cryptography import x509
        from cryptography.hazmat.backends import default_backend
        
        with open(cert_path, "rb") as f:
            cert_data = f.read()
        
        cert = x509.load_pem_x509_certificate(cert_data, default_backend())
        
        print("\n📄 Certificate Information:")
        print(f"  Subject: {cert.subject}")
        print(f"  Issuer: {cert.issuer}")
        print(f"  Serial: {cert.serial_number}")
        print(f"  Valid from: {cert.not_valid_before_utc}")
        print(f"  Valid until: {cert.not_valid_after_utc}")
        print(f"  Signature algorithm: {cert.signature_algorithm_oid}")
        
        # Check expiration - ✅ FIXED: Use timezone-aware datetime
        now = datetime.now(timezone.utc)
        print(f"  Current time (UTC): {now}")
        
        if cert.not_valid_after_utc < now:
            print(f"  ❌ EXPIRED: {cert.not_valid_after_utc} < {now}")
        else:
            print(f"  ✅ Not expired")
        
        if cert.not_valid_before_utc > now:
            print(f"  ❌ Not yet valid: {cert.not_valid_before_utc} > {now}")
        else:
            print(f"  ✅ Valid from date passed")
        
        # Verify with CA
        print("\n🔐 Verifying with CA...")
        print(f"  CA Certificate: {certificate_generator.ca_cert_path}")
        print(f"  CA exists: {Path(certificate_generator.ca_cert_path).exists()}")
        
        if not Path(certificate_generator.ca_cert_path).exists():
            print("  ❌ CA certificate not found!")
            return
        
        ca_public_key = certificate_generator.ca_cert.public_key()
        
        try:
            ca_public_key.verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                cert.signature_hash_algorithm,
                cert.signature_algorithm_parameters
            )
            print("  ✅ Signature verification PASSED")
            print("\n🎉 Certificate is VALID!")
        except Exception as e:
            print(f"  ❌ Signature verification FAILED: {e}")
            print("\n❌ Certificate is INVALID")
        
    except Exception as e:
        print(f"Error reading certificate: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()