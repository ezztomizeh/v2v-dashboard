from datetime import datetime
from typing import Optional, Literal, List
from pydantic import BaseModel, Field, ConfigDict
from utils.object_id import PyObjectId


class RevocationInfo(BaseModel):
    revoked_at: Optional[datetime] = Field(None, description="When the certificate was revoked")
    revoked_by: Optional[PyObjectId] = Field(None, description="User who revoked the certificate")
    revocation_reason: Optional[str] = Field(None, description="Reason for revocation")
    revocation_date: Optional[datetime] = Field(None, description="When revocation becomes effective")


class CertificateBase(BaseModel):
    """Base certificate model"""
    certificate_id: str = Field(..., description="Unique certificate identifier")
    license_plate: str = Field(..., description="Vehicle license plate")
    status: Literal["regular", "emergency", "stolen", "revoked", "expired", "suspended"] = Field(
        ..., description="Current certificate status"
    )
    valid_from: datetime = Field(..., description="Certificate validity start date")
    valid_until: datetime = Field(..., description="Certificate validity end date")
    issuer_ca: str = Field(..., description="Issuing Certificate Authority")


class CertificateModel(CertificateBase):
    """Complete certificate document model"""
    id: Optional[PyObjectId] = Field(alias="_id", default=None, description="MongoDB document ID")
    
    # Relationships
    vehicle_id: PyObjectId = Field(..., description="Reference to vehicle")
    owner_national_id: Optional[str] = Field(None, description="Vehicle owner national ID")
    
    # File paths
    public_key_path: str = Field(..., description="Path to public key file")
    private_key_path: str = Field(..., description="Path to private key file")
    certificate_path: str = Field(..., description="Path to certificate file")
    csr_path: Optional[str] = Field(None, description="Path to CSR file if applicable")
    
    # Certificate details
    serial_number: str = Field(..., description="Certificate serial number")
    key_algorithm: str = Field("RSA", description="Key algorithm used")
    key_size: int = Field(2048, description="Key size in bits")
    signature_algorithm: str = Field("SHA256withRSA", description="Signature algorithm")
    
    # Status tracking
    previous_status: Optional[str] = Field(None, description="Previous status before change")
    status_reason: Optional[str] = Field(None, description="Reason for status change")
    status_changed_at: Optional[datetime] = Field(None, description="When status was last changed")
    status_changed_by: Optional[PyObjectId] = Field(None, description="User who changed status")
    
    # Usage tracking
    last_used: Optional[datetime] = Field(None, description="Last time certificate was used")
    last_used_ip: Optional[str] = Field(None, description="IP address of last use")
    usage_count: int = Field(0, description="Number of times certificate was used")
    
    # Revocation info
    revocation: RevocationInfo = Field(default_factory=RevocationInfo, description="Revocation details")
    
    # Audit
    created_at: datetime = Field(default_factory=datetime.now, description="Creation timestamp")
    created_by: Optional[PyObjectId] = Field(None, description="User who created this record")
    updated_at: datetime = Field(default_factory=datetime.now, description="Last update timestamp")
    notes: Optional[str] = Field(None, description="Additional notes")

    model_config = ConfigDict(
        populate_by_name=True,
        arbitrary_types_allowed=True,
        json_schema_extra={
            "example": {
                "certificate_id": "CERT-2026-001-ABC123",
                "license_plate": "ABC-1234",
                "vehicle_id": "67b5a8c1f1a2b3c4d5e6f7g8",
                "status": "regular",
                "public_key_path": "/certs/vehicles/public/ABC-1234_20260220.pem",
                "private_key_path": "/certs/vehicles/private/ABC-1234_20260220.key",
                "certificate_path": "/certs/vehicles/certs/ABC-1234_20260220.crt",
                "valid_from": "2026-02-20T00:00:00Z",
                "valid_until": "2027-02-20T00:00:00Z",
                "serial_number": "1234567890ABCDEF",
                "issuer_ca": "PPU-V2V-CA-ROOT-01"
            }
        }
    )


class CertificateCreateModel(BaseModel):
    """Model for creating a new certificate"""
    vehicle_id: str = Field(..., description="Vehicle ID to issue certificate for")
    status: Literal["regular", "emergency"] = Field("regular", description="Initial certificate status")
    validity_days: Optional[int] = Field(365, description="Certificate validity in days", ge=1, le=730)
    notes: Optional[str] = Field(None, description="Additional notes")

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "vehicle_id": "67b5a8c1f1a2b3c4d5e6f7g8",
                "status": "regular",
                "validity_days": 365,
                "notes": "Initial certificate issuance"
            }
        }
    )


class CertificateUpdateModel(BaseModel):
    """Model for updating a certificate"""
    status: Optional[Literal["regular", "emergency", "stolen", "revoked", "suspended"]] = Field(
        None, description="New certificate status"
    )
    status_reason: Optional[str] = Field(None, description="Reason for status change")
    notes: Optional[str] = Field(None, description="Additional notes")

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "status": "emergency",
                "status_reason": "Vehicle converted to emergency services",
                "notes": "Priority access granted"
            }
        }
    )

class CertificateResponse(BaseModel):
    """Response model for certificates - all fields are JSON-serializable"""
    id: str = Field(..., alias="_id", description="Certificate ID")
    certificate_id: str = Field(..., description="Unique certificate identifier")
    serial_number: str = Field(..., description="Certificate serial number")
    license_plate: str = Field(..., description="Vehicle license plate")
    vehicle_id: str = Field(..., description="Reference to vehicle")
    owner_national_id: Optional[str] = Field(None, description="Vehicle owner national ID")
    
    # File paths
    public_key_path: str = Field(..., description="Path to public key file")
    private_key_path: str = Field(..., description="Path to private key file")
    certificate_path: str = Field(..., description="Path to certificate file")
    csr_path: Optional[str] = Field(None, description="Path to CSR file")
    
    # Status
    status: str = Field(..., description="Current certificate status")
    previous_status: Optional[str] = Field(None, description="Previous status")
    status_reason: Optional[str] = Field(None, description="Reason for status change")
    status_changed_at: Optional[str] = Field(None, description="When status was last changed")
    status_changed_by: Optional[str] = Field(None, description="User who changed status")
    
    # Validity
    valid_from: str = Field(..., description="Certificate validity start date")
    valid_until: str = Field(..., description="Certificate validity end date")
    
    # Certificate details
    key_algorithm: str = Field(..., description="Key algorithm used")
    key_size: int = Field(..., description="Key size in bits")
    signature_algorithm: str = Field(..., description="Signature algorithm")
    issuer_ca: str = Field(..., description="Issuing Certificate Authority")
    issuer_certificate_id: str = Field(..., description="Issuer certificate ID")
    
    # Usage tracking
    last_used: Optional[str] = Field(None, description="Last time certificate was used")
    last_used_ip: Optional[str] = Field(None, description="IP address of last use")
    usage_count: int = Field(0, description="Number of times certificate was used")
    
    # Audit
    created_at: str = Field(..., description="Creation timestamp")
    created_by: Optional[str] = Field(None, description="User who created this record")
    updated_at: Optional[str] = Field(None, description="Last update timestamp")
    notes: Optional[str] = Field(None, description="Additional notes")

    model_config = ConfigDict(
        populate_by_name=True,
        json_schema_extra={
            "example": {
                "id": "69986a051abc539ea8290d9d",
                "certificate_id": "CERT-2026-E88EA2A8",
                "license_plate": "ABC-1234",
                "vehicle_id": "69971266294658161f4844b9",
                "status": "regular",
                "valid_from": "2026-02-20T14:01:08",
                "valid_until": "2027-02-20T14:01:08",
                "created_at": "2026-02-20T14:01:08.679000"
            }
        }
    )


class CertificateListResponse(BaseModel):
    """Response model for list of certificates"""
    items: List[CertificateResponse]
    total: int
    skip: int
    limit: int