import os
import shutil
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, Tuple, Optional
import uuid

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from cryptography.hazmat.backends import default_backend

from config.settings import settings


class CertificateGenerator:
    
    def __init__(self):
        self.ca_cert_path = Path(settings.CA_CERT_PATH)
        self.ca_key_path = Path(settings.CA_KEY_PATH)
        self.certs_dir = Path(settings.CERTIFICATES_PATH)
        self.private_keys_dir = Path(settings.PRIVATE_KEYS_PATH)
        self.public_keys_dir = Path(settings.PUBLIC_KEYS_PATH)
        
        self._create_directories()
        
        self.ca_cert, self.ca_key = self._load_ca_certificate()
    
    def _create_directories(self):
        directories = [
            self.certs_dir,
            self.private_keys_dir,
            self.public_keys_dir
        ]
        
        for directory in directories:
            directory.mkdir(parents=True, exist_ok=True)
            if directory == self.private_keys_dir:
                os.chmod(directory, 0o700)
    
    def _load_ca_certificate(self) -> Tuple[x509.Certificate, RSAPrivateKey]:
        if not self.ca_cert_path.exists() or not self.ca_key_path.exists():
            return self._create_ca_certificate()
        
        try:
            with open(self.ca_key_path, "rb") as key_file:
                ca_key = serialization.load_pem_private_key(
                    key_file.read(),
                    password=None,  
                    backend=default_backend()
                )
            
            
            with open(self.ca_cert_path, "rb") as cert_file:
                ca_cert = x509.load_pem_x509_certificate(
                    cert_file.read(),
                    backend=default_backend()
                )
            
            return ca_cert, ca_key
            
        except Exception as e:
            print(f"Error loading CA certificate: {e}")
            return self._create_ca_certificate()
    
    def _create_vehicle_certificate(self,
                                    vehicle_data: Dict,
                                    public_key: RSAPublicKey,
                                    validity_days: int,
                                    cert_id: str
                                    ) -> x509.Certificate:
        timestamp_part = int(datetime.utcnow().timestamp()) & 0xFFFFFFFF  
        random_part = uuid.uuid4().int & 0xFFFFFFFF  
        mongo_compatible_serial = (timestamp_part << 32) | random_part  
        
        subject = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "PS"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Palestine"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, vehicle_data.get("city", "Hebron")),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "V2V System"),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Vehicles"),
            x509.NameAttribute(NameOID.COMMON_NAME, vehicle_data["license_plate"]),
            x509.NameAttribute(NameOID.SERIAL_NUMBER, vehicle_data.get("chassis_number", "")),
        ])
        
        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            self.ca_cert.subject  
        ).public_key(
            public_key
        ).serial_number(
            mongo_compatible_serial  
        ).not_valid_before(
            datetime.utcnow()
        ).not_valid_after(
            datetime.utcnow() + timedelta(days=validity_days)
        ).add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName(f"vehicle-{vehicle_data['license_plate']}.v2v.local"),
                x509.DNSName(f"obu-{vehicle_data.get('hardware', {}).get('obu_id', 'unknown')}.v2v.local")
            ]),
            critical=False
        ).add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True
        ).add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False
            ),
            critical=True
        ).add_extension(
            x509.ExtendedKeyUsage([
                x509.ExtendedKeyUsageOID.CLIENT_AUTH,
                x509.oid.ExtendedKeyUsageOID.EMAIL_PROTECTION
            ]),
            critical=False
        ).add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(self.ca_key.public_key()),
            critical=False
        ).add_extension(
            x509.SubjectKeyIdentifier.from_public_key(public_key),
            critical=False
        ).add_extension(
            # Custom extension for vehicle status
            x509.UnrecognizedExtension(
                oid=x509.ObjectIdentifier("1.3.6.1.4.1.99999.1.1"),
                value=f"status:regular;id:{cert_id}".encode()
            ),
            critical=False
        ).sign(self.ca_key, hashes.SHA256(), default_backend())
        
        return cert
    
    def _save_ca_certificate(self, ca_cert: x509.Certificate, ca_key: RSAPrivateKey):
        with open(self.ca_key_path, "wb") as key_file:
            key_file.write(ca_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))
        os.chmod(self.ca_key_path, 0o600)
        
        with open(self.ca_cert_path, "wb") as cert_file:
            cert_file.write(ca_cert.public_bytes(serialization.Encoding.PEM))
    
    def generate_vehicle_certificate(
        self, 
        vehicle_data: Dict,
        validity_days: int = 365
    ) -> Dict:
        cert_id = f"CERT-{datetime.now().year}-{uuid.uuid4().hex[:8].upper()}"
        
        license_plate = vehicle_data["license_plate"].replace(" ", "_")
        timestamp = datetime.now().strftime("%Y%m%d")
        
        private_key, public_key = self._generate_key_pair()
        
        certificate = self._create_vehicle_certificate(
            vehicle_data, 
            public_key, 
            validity_days,
            cert_id
        )
        
        file_paths = self._save_certificate_files(
            license_plate,
            timestamp,
            cert_id,
            certificate,
            private_key,
            public_key
        )
        
        cert_data = {
            "certificate_id": cert_id,
            "serial_number": str(certificate.serial_number),
            "license_plate": vehicle_data["license_plate"],
            "vehicle_id": vehicle_data.get("vehicle_id"),
            "owner_national_id": vehicle_data.get("owner_national_id"),
            "public_key_path": file_paths["public_key"],
            "private_key_path": file_paths["private_key"],
            "certificate_path": file_paths["certificate"],
            "csr_path": file_paths.get("csr"),
            "status": "regular",  # Default status
            "valid_from": certificate.not_valid_before_utc,
            "valid_until": certificate.not_valid_after_utc,
            "key_algorithm": "RSA",
            "key_size": 2048,
            "signature_algorithm": "SHA256withRSA",
            "issuer_ca": "PPU-V2V-CA-ROOT-01",
            "issuer_certificate_id": self._get_ca_serial(),
            "created_at": datetime.utcnow()
        }
        
        return cert_data
    
    def _generate_key_pair(self) -> Tuple[RSAPrivateKey, RSAPublicKey]:
        """Generate RSA key pair for vehicle"""
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,  # 2048 bits is sufficient for vehicle certificates
            backend=default_backend()
        )
        public_key = private_key.public_key()
        
        return private_key, public_key
    
    def _create_vehicle_certificate(
        self,
        vehicle_data: Dict,
        public_key: RSAPublicKey,
        validity_days: int,
        cert_id: str
    ) -> x509.Certificate:

        subject = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "PS"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Palestine"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, vehicle_data.get("city", "Hebron")),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "V2V System"),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Vehicles"),
            x509.NameAttribute(NameOID.COMMON_NAME, vehicle_data["license_plate"]),
            x509.NameAttribute(NameOID.SERIAL_NUMBER, vehicle_data.get("chassis_number", "")),
        ])
        
        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            self.ca_cert.subject
        ).public_key(
            public_key
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.utcnow()
        ).not_valid_after(
            datetime.utcnow() + timedelta(days=validity_days)
        ).add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName(f"vehicle-{vehicle_data['license_plate']}.v2v.local"),
                x509.DNSName(f"obu-{vehicle_data.get('hardware', {}).get('obu_id', 'unknown')}.v2v.local")
            ]),
            critical=False
        ).add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True
        ).add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False
            ),
            critical=True
        ).add_extension(
            x509.ExtendedKeyUsage([
                x509.ExtendedKeyUsageOID.CLIENT_AUTH,
                x509.oid.ExtendedKeyUsageOID.EMAIL_PROTECTION
            ]),
            critical=False
        ).add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(self.ca_key.public_key()),
            critical=False
        ).add_extension(
            x509.SubjectKeyIdentifier.from_public_key(public_key),
            critical=False
        ).add_extension(
            x509.UnrecognizedExtension(
                oid=x509.ObjectIdentifier("1.3.6.1.4.1.99999.1.1"),  # Private OID for V2V
                value=f"status:regular;id:{cert_id}".encode()
            ),
            critical=False
        ).sign(self.ca_key, hashes.SHA256(), default_backend())
        
        return cert
    
    def _save_certificate_files(
        self,
        license_plate: str,
        timestamp: str,
        cert_id: str,
        certificate: x509.Certificate,
        private_key: RSAPrivateKey,
        public_key: RSAPublicKey
    ) -> Dict:
        base_filename = f"{license_plate}_{timestamp}_{cert_id[-8:]}"
        
        cert_path = self.certs_dir / f"{base_filename}.crt"
        private_key_path = self.private_keys_dir / f"{base_filename}.key"
        public_key_path = self.public_keys_dir / f"{base_filename}.pem"
        
        with open(cert_path, "wb") as f:
            f.write(certificate.public_bytes(serialization.Encoding.PEM))
        
        with open(private_key_path, "wb") as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                # In production, use encryption:
                # encryption_algorithm=serialization.BestAvailableEncryption(b"vehicle-password")
                encryption_algorithm=serialization.NoEncryption()  # For development
            ))
        os.chmod(private_key_path, 0o600)  # Secure permissions
        
        # Save public key
        with open(public_key_path, "wb") as f:
            f.write(public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))
        
        return {
            "certificate": str(cert_path),
            "private_key": str(private_key_path),
            "public_key": str(public_key_path)
        }
    
    def _get_ca_serial(self) -> str:
        """Get CA certificate serial number as string"""
        return str(self.ca_cert.serial_number)
    
    def revoke_certificate(self, certificate_path: Path, reason: str = "stolen") -> Path:
        """
        Revoke a certificate by moving it to a revoked directory
        """
        revoked_dir = self.certs_dir / "revoked"
        revoked_dir.mkdir(exist_ok=True)
        
        # Move certificate to revoked directory
        revoked_path = revoked_dir / certificate_path.name
        shutil.move(str(certificate_path), str(revoked_path))
        
        # Create a revocation record
        crl_entry = revoked_dir / "crl.txt"
        with open(crl_entry, "a") as f:
            f.write(f"{datetime.utcnow().isoformat()},{certificate_path.name},{reason}\n")
        
        return revoked_path
    
    def verify_certificate(self, certificate_path: Path) -> bool:
        """
        Verify if a certificate is valid and signed by our CA
        """
        try:
            # Check if file exists
            if not certificate_path.exists():
                print(f"Certificate file not found: {certificate_path}")
                return False
            
            # Load certificate
            with open(certificate_path, "rb") as f:
                cert_data = f.read()
            
            # Load certificate
            cert = x509.load_pem_x509_certificate(cert_data, default_backend())
            
            # Debug: Print certificate info
            print(f"Certificate subject: {cert.subject}")
            print(f"Certificate issuer: {cert.issuer}")
            
            # Check expiration
            now = datetime.now(timezone.utc)
            if cert.not_valid_after_utc < now:
                print(f"Certificate expired")
                return False
            
            # ✅ SIMPLER FIX: Let the cryptography library handle the hash algorithm
            # by using the CA certificate's public key to verify
            ca_public_key = self.ca_cert.public_key()
            
            # The verify method can extract the hash algorithm from the certificate
            try:
                # This is the standard way to verify a certificate signature
                ca_public_key.verify(
                    cert.signature,
                    cert.tbs_certificate_bytes,
                    padding.PKCS1v15(),
                    cert.signature_hash_algorithm  # This should be a hash algorithm instance
                )
                print("Signature verification passed")
            except AttributeError:
                # If cert.signature_hash_algorithm is returning an OID instead of an instance
                # We need to map it manually
                from cryptography.hazmat.primitives import hashes
                
                # Get the OID as string
                sig_oid = cert.signature_algorithm_oid
                print(f"Signature algorithm OID: {sig_oid.dotted_string}")
                
                # Map common OIDs to hash algorithms
                if sig_oid.dotted_string in ['1.2.840.113549.1.1.11', '2.16.840.1.101.3.4.2.1']:
                    hash_algo = hashes.SHA256()
                elif sig_oid.dotted_string in ['1.2.840.113549.1.1.12', '2.16.840.1.101.3.4.2.2']:
                    hash_algo = hashes.SHA384()
                elif sig_oid.dotted_string in ['1.2.840.113549.1.1.13', '2.16.840.1.101.3.4.2.3']:
                    hash_algo = hashes.SHA512()
                elif sig_oid.dotted_string == '1.2.840.113549.1.1.5':
                    hash_algo = hashes.SHA1()
                else:
                    print(f"Unsupported signature algorithm: {sig_oid.dotted_string}")
                    return False
                
                ca_public_key.verify(
                    cert.signature,
                    cert.tbs_certificate_bytes,
                    padding.PKCS1v15(),
                    hash_algo
                )
                print(f"Signature verification passed with {hash_algo.name}")
            
            return True
            
        except Exception as e:
            print(f"Certificate verification failed: {e}")
            import traceback
            traceback.print_exc()
            return False
        
        
    def generate_csr(self, vehicle_data: Dict) -> Tuple[str, RSAPrivateKey]:
        """
        Generate a Certificate Signing Request (CSR) for a vehicle
        Useful if vehicles generate their own keys
        """
        # Generate key pair
        private_key, public_key = self._generate_key_pair()
        
        # Create CSR
        csr = x509.CertificateSigningRequestBuilder().subject_name(
            x509.Name([
                x509.NameAttribute(NameOID.COUNTRY_NAME, "PS"),
                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Palestine"),
                x509.NameAttribute(NameOID.LOCALITY_NAME, vehicle_data.get("city", "Hebron")),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "V2V System"),
                x509.NameAttribute(NameOID.COMMON_NAME, vehicle_data["license_plate"]),
            ])
        ).add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName(f"vehicle-{vehicle_data['license_plate']}.v2v.local")
            ]),
            critical=False
        ).sign(private_key, hashes.SHA256(), default_backend())
        
        # Convert CSR to PEM
        csr_pem = csr.public_bytes(serialization.Encoding.PEM).decode()
        
        return csr_pem, private_key


# Create singleton instance
certificate_generator = CertificateGenerator()


async def generate_certificate(vehicle_data: Dict, validity_days: int = 365) -> Dict:
    """
    Wrapper function for certificate generation (to be used in API endpoints)
    """
    return certificate_generator.generate_vehicle_certificate(vehicle_data, validity_days)