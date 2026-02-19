from datetime import datetime
from typing import Optional, Literal
from pydantic import BaseModel, Field, ConfigDict
from utils.object_id import PyObjectId

class RevocationModel(BaseModel):
    reason: str = Field(..., description="Reason for revocation")
    revoked_at: datetime = Field(default_factory=datetime.now())
    revoked_by: Optional[str] = Field(None, description="admin")

class CertificateModel(BaseModel):
    id: Optional[PyObjectId] = Field(alias="_id", default=None)
    certificate_id: str = Field(..., description="CERT-2026-001-ABC123")

    # Relationships
    vehicle_id: PyObjectId = Field(..., description="ID of the associated vehicle")
    license_plate: str = Field(..., description="ABC-1234")
    onwer_national_id: str = Field(..., description="1234567890")

    # file path or URL to the certificate document
    public_key_path: str
    certificate_path: str
    csr_path: str

    # Status Tracking 
    status: Literal["regular", "emergency", "stolen", "revoked"] = Field(default="regular", description="Current status of the certificate")
    previous_status: Optional[Literal["regular", "emergency", "stolen", "revoked"]] = Field(None, description="Previous status of the certificate")
    status_changed_at: Optional[datetime] = Field(None, description="Timestamp of the last status change")
    status_changed_by: Optional[PyObjectId] = Field(None, description="User who changed the status")
    status_change_reason: Optional[str] = Field(None, description="Reason for the status change")

    # Validity Period
    valid_from: datetime = Field(default_factory=datetime.now, description="Certificate validity start date")
    valid_to: datetime = Field(..., description="Certificate validity end date")

    # Crypto detials
    key_algorithm: str = "RSA"
    key_size: int = 2048
    signature_algorithm: str = "SHA256withRSA"
    serial_number: str = Field(..., description="Unique serial number for the certificate")

    # Issuer
    issuer_ca: str = "PPU-CA-ROOT-01"
    issuer_certificate_id: str

    # Usage tracking
    last_used_at: Optional[datetime] = Field(None, description="Timestamp of the last use of the certificate")
    last_used_ip: Optional[str] = Field(None, description="IP address from which the certificate was last used")
    usage_count: int = Field(0, description="Number of times the certificate has been used")

    # Revocation details
    revocation: Optional[RevocationModel] = Field(None, description="Revocation details if the certificate is revoked")

    # Audit
    created_at: datetime = Field(default_factory=datetime.now)
    updated_at: datetime = Field(default_factory=datetime.now)
    created_by: Optional[PyObjectId] = Field(None, description="User who created the certificate")

    model_config = ConfigDict(
        populate_by_name=True,
        arbitrary_types_allowed=True,
        json_schema_extra={
            "example": {
                "certificate_id": "CERT-2026-001-ABC123",
                "vehicle_id": "64b8f0c2e1d3f5a2b3c4d5e6f7g8h9i0j12k3l4m5n6o7p8q9r0s1t2u3v4w5x6y7z8a9b0c1d",
                "license_plate": "ABC-1234",
                "onwer_national_id": "1234567890",
                "public_key_path": "/path/to/public_key.pem",
                "certificate_path": "/path/to/certificate.pem",
                "csr_path": "/path/to/csr.pem",
                "status": "regular",
                "valid_from": "2024-01-01T00:00:00Z",
                "valid_to": "2025-01-01T00:00:00Z",
                "key_algorithm": "RSA",
                "key_size": 2048,
                "signature_algorithm": "SHA256withRSA",
                "serial_number": "1234567890ABCDEF",
                "issuer_ca": "PPU-CA-ROOT-01",
                "issuer_certificate_id": "CERT-ROOT-001",
                "last_used_at": "2024-06-01T12:00:00Z",
                "last_used_ip": "192.255.255.255",
                "usage_count": 5,
                "revocation": {
                    "reason": "Key compromise",
                    "revoked_at": "2024-06-15T12:00:00Z",
                    "revoked_by": "admin"
                },
                "created_at": "2024-01-01T00:00:00Z",
                "updated_at": "2024-06-15T12:00:00Z",
                "created_by": "admin"
            }
        }
    )
    