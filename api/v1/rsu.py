from fastapi import APIRouter, HTTPException, Depends, status
from datetime import datetime, timezone
from pathlib import Path
from bson import ObjectId

from core.security import get_current_api_key
from config.database import get_database
from services.certificate_generator import certificate_generator

router = APIRouter(prefix="/rsu", tags=["RSU Endpoints"])


@router.get("/verify-certificate/{certificate_id}")
async def rsu_verify_certificate(
    certificate_id: str,
    api_key: dict = Depends(get_current_api_key),
    db = Depends(get_database)
):
    """
    Verify a certificate (RSUs use API key)
    """
    # Check if certificate exists
    cert = None
    
    # Try by ObjectId first
    if ObjectId.is_valid(certificate_id):
        cert = await db.certificates.find_one({"_id": ObjectId(certificate_id)})
    
    # Try by certificate_id field
    if not cert:
        cert = await db.certificates.find_one({"certificate_id": certificate_id})
    
    if not cert:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Certificate not found"
        )
    
    # Quick check from database
    if cert["status"] in ["revoked", "stolen", "expired"]:
        return {
            "valid": False,
            "status": cert["status"],
            "reason": f"Certificate is {cert['status']}"
        }
    
    # Check expiration
    valid_until = cert["valid_until"]
    if isinstance(valid_until, str):
        from dateutil import parser
        valid_until = parser.isoparse(valid_until)
    
    if valid_until.tzinfo is None:
        from datetime import timezone
        valid_until = valid_until.replace(tzinfo=timezone.utc)
    
    if valid_until < datetime.now(timezone.utc):
        return {
            "valid": False,
            "status": "expired",
            "reason": "Certificate has expired"
        }
    
    # Verify file
    cert_path = Path(cert["certificate_path"])
    crypto_valid = False
    
    if cert_path.exists():
        crypto_valid = certificate_generator.verify_certificate(cert_path)
    
    # Update last used
    await db.certificates.update_one(
        {"_id": cert["_id"]},
        {
            "$set": {
                "last_used": datetime.now(timezone.utc),
                "last_used_ip": "rsu",
                "$inc": {"usage_count": 1}
            }
        }
    )
    
    return {
        "valid": crypto_valid,
        "status": cert["status"],
        "license_plate": cert["license_plate"],
        "valid_from": cert["valid_from"],
        "valid_until": cert["valid_until"]
    }


@router.get("/check-revocation/{certificate_id}")
async def rsu_check_revocation(
    certificate_id: str,
    api_key: dict = Depends(get_current_api_key),
    db = Depends(get_database)
):
    """
    Check if a certificate is revoked (RSUs use API key)
    """
    # Check in revocations collection
    revoked = await db.certificate_revocations.find_one({
        "certificate_id": certificate_id
    })
    
    if revoked:
        return {
            "revoked": True,
            "reason": revoked.get("revocation_reason"),
            "date": revoked.get("revocation_date")
        }
    
    # Double-check certificate status
    cert = None
    if ObjectId.is_valid(certificate_id):
        cert = await db.certificates.find_one({"_id": ObjectId(certificate_id)})
    
    if not cert:
        cert = await db.certificates.find_one({"certificate_id": certificate_id})
    
    if cert and cert["status"] in ["revoked", "stolen"]:
        return {
            "revoked": True,
            "reason": cert["status"],
            "date": cert.get("status_changed_at")
        }
    
    return {"revoked": False}


@router.get("/vehicle/{license_plate}")
async def rsu_get_vehicle(
    license_plate: str,
    api_key: dict = Depends(get_current_api_key),
    db = Depends(get_database)
):
    """
    Get vehicle information (RSUs use API key)
    """
    vehicle = await db.vehicles.find_one({"license_plate": license_plate})
    
    if not vehicle:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Vehicle not found"
        )
    
    # Get active certificate
    active_cert = await db.certificates.find_one({
        "vehicle_id": vehicle["_id"],
        "status": {"$in": ["regular", "emergency"]},
        "valid_until": {"$gt": datetime.now(timezone.utc)}
    })
    
    return {
        "license_plate": vehicle["license_plate"],
        "vehicle_type": vehicle["vehicle_type"],
        "manufacturer": vehicle["manufacturer"],
        "model": vehicle["model"],
        "color": vehicle["color"],
        "has_active_certificate": active_cert is not None,
        "certificate_status": active_cert["status"] if active_cert else None,
        "certificate_id": str(active_cert["_id"]) if active_cert else None
    }