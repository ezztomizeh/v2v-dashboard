from fastapi import APIRouter, Depends, HTTPException, status, BackgroundTasks
from typing import List
from bson import ObjectId
from datetime import datetime, timedelta, timezone
from pathlib import Path

from models.certificate import CertificateModel, CertificateCreateModel, CertificateUpdateModel, CertificateResponse
from config.database import get_database
from services.certificate_generator import generate_certificate, certificate_generator
from utils.object_id import convert_objectid_to_str, prepare_response

router = APIRouter(prefix="/certificates", tags=["Certificates"])

@router.post("/", response_model=CertificateModel, status_code=status.HTTP_201_CREATED)
async def issue_certificate(
    certificate_data: CertificateCreateModel,
    background_tasks: BackgroundTasks,
    db = Depends(get_database)
):
    """
    Issue a new certificate for a vehicle
    """
    # Check if vehicle exists
    vehicle = await db.vehicles.find_one({"_id": ObjectId(certificate_data.vehicle_id)})
    if not vehicle:
        raise HTTPException(status_code=404, detail="Vehicle not found")
    
    # Check for existing active certificate
    existing = await db.certificates.find_one({
        "vehicle_id": ObjectId(certificate_data.vehicle_id),
        "status": {"$in": ["regular", "emergency"]},
        "valid_until": {"$gt": datetime.utcnow()}
    })
    
    if existing:
        raise HTTPException(
            status_code=400,
            detail="Vehicle already has an active certificate"
        )
    
    # Prepare vehicle data for certificate generation
    vehicle_info = {
        "vehicle_id": str(vehicle["_id"]),
        "license_plate": vehicle["license_plate"],
        "chassis_number": vehicle["chassis_number"],
        "owner_national_id": vehicle["owner"]["national_id"],
        "owner_name": vehicle["owner"]["full_name"],
        "city": vehicle["owner"]["address"].get("city", "Hebron"),
        "hardware": vehicle.get("hardware", {})
    }
    
    try:
        # Generate certificate
        cert_data = await generate_certificate(
            vehicle_info, 
            validity_days=certificate_data.validity_days or 365
        )
        
        # Add metadata
        cert_data["vehicle_id"] = ObjectId(certificate_data.vehicle_id)
        cert_data["created_by"] = ObjectId("000000000000000000000001")  # Placeholder for admin user ID
        cert_data["status"] = certificate_data.status or "regular"
        cert_data["notes"] = certificate_data.notes
        
        # Insert into database
        result = await db.certificates.insert_one(cert_data)
        
        # Fetch created certificate
        created = await db.certificates.find_one({"_id": result.inserted_id})
        created = prepare_response(created)
        
        # Update vehicle with certificate reference (optional)
        await db.vehicles.update_one(
            {"_id": ObjectId(certificate_data.vehicle_id)},
            {"$set": {"current_certificate_id": str(result.inserted_id)}}
        )
        
        return created
        
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Certificate generation failed: {str(e)}"
        )

@router.get("/", response_model=List[CertificateResponse])
async def list_certificates(skip: int = 0, limit: int = 100, status: str = None, db=Depends(get_database)):
    query = {}
    if status:
        query["status"] = status
    
    # Get total count for pagination
    total = await db.certificates.count_documents(query)
    
    cursor = db.certificates.find(query).skip(skip).limit(limit)
    certificates = await cursor.to_list(length=limit)
    
    # Convert each certificate
    converted = []
    for cert in certificates:
        converted.append({
            "_id": str(cert["_id"]),
            "certificate_id": cert["certificate_id"],
            "serial_number": cert["serial_number"],
            "license_plate": cert["license_plate"],
            "vehicle_id": str(cert["vehicle_id"]),
            "owner_national_id": cert.get("owner_national_id"),
            "public_key_path": cert["public_key_path"],
            "private_key_path": cert["private_key_path"],
            "certificate_path": cert["certificate_path"],
            "csr_path": cert.get("csr_path"),
            "status": cert["status"],
            "previous_status": cert.get("previous_status"),
            "status_reason": cert.get("status_reason"),
            "status_changed_at": cert["status_changed_at"].isoformat() if cert.get("status_changed_at") else None,
            "status_changed_by": str(cert["status_changed_by"]) if cert.get("status_changed_by") else None,
            "valid_from": cert["valid_from"].isoformat(),
            "valid_until": cert["valid_until"].isoformat(),
            "key_algorithm": cert["key_algorithm"],
            "key_size": cert["key_size"],
            "signature_algorithm": cert["signature_algorithm"],
            "issuer_ca": cert["issuer_ca"],
            "issuer_certificate_id": cert["issuer_certificate_id"],
            "last_used": cert["last_used"].isoformat() if cert.get("last_used") else None,
            "last_used_ip": cert.get("last_used_ip"),
            "usage_count": cert.get("usage_count", 0),
            "created_at": cert["created_at"].isoformat(),
            "created_by": str(cert["created_by"]) if cert.get("created_by") else None,
            "updated_at": cert["updated_at"].isoformat() if cert.get("updated_at") else None,
            "notes": cert.get("notes")
        })
    
    # If using CertificateListResponse
    # return {"items": converted, "total": total, "skip": skip, "limit": limit}
    
    return converted


@router.get("/{certificate_id}", response_model=CertificateModel)
async def get_certificate(certificate_id: str, db=Depends(get_database)):
    if not ObjectId.is_valid(certificate_id):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid certificate ID")
    cert = await db.certificates.find_one({"_id": ObjectId(certificate_id)})
    if not cert:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Certificate not found")
    cert = prepare_response(cert)
    return cert

@router.patch("/{certificate_id}/status", response_model=CertificateModel)
async def update_certificate_status(certificate_id: str,
                                     status_update: dict,
                                     background_tasks: BackgroundTasks,
                                     db=Depends(get_database)):
    
    valid_statuses = ["regular", "emergency", "stolen", "revoked", "expired", "suspended"]

    if status_update.get("status") not in valid_statuses:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid status value")
    if not ObjectId.is_valid(certificate_id):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid certificate ID")
    
    certificate = await db.certificates.find_one({"_id": ObjectId(certificate_id)})
    if not certificate:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Certificate not found")
    
    old_status = certificate["status"]
    new_status = status_update["status"]

    if new_status in ["stolen","revoked"]:
        cert_path = Path(certificate["certificate_path"])
        if cert_path.exists():
            background_tasks.add_task(certificate_generator.revoke_certificate,
                                    cert_path,
                                    reason=new_status)
        revocation = {
            "certificate_id": certificate_id,
            "certificate_serial": certificate["serial_number"],
            "license_plate": certificate["license_plate"],
            "revocation_reason": new_status,
            "revocation_date": datetime.utcnow(),
            "effective_date": datetime.utcnow(),
            "revoked_by": ObjectId("000000000000000000000001"),  # Placeholder for admin user ID
            "notes": status_update.get("reason", "")
        }
        await db.certificate_revocations.insert_one(revocation)

    update_data = {
        "status": new_status,
        "previous_status": old_status,
        "status_changed_at": datetime.utcnow(),
        "status_changed_by": ObjectId("000000000000000000000001"),  # Placeholder for admin user ID
        "status_reason": status_update.get("reason"),
        "updated_at": datetime.utcnow()
    }

    await db.certificates.update_one(
        {"_id": ObjectId(certificate_id)},
        {"$set": update_data}
    )

    if new_status in ["stolen"]:
        await db.vehicles.update_one(
            {"_id": ObjectId(certificate["vehicle_id"])},
            {"$set": 
               {
                "status": "stolen",
                "updated_at": datetime.utcnow()
               }
            }
        )
    return {
        "message": f"Certificate status updated to {new_status} from {old_status}",
        "certificate_id": certificate_id,
    }

@router.get("/{certificate_id}/verify")
async def verify_certificate(
    certificate_id: str,
    check_revocation: bool = True,
    db = Depends(get_database)
):

    if not ObjectId.is_valid(certificate_id):
        raise HTTPException(status_code=400, detail="Invalid certificate ID")
    
    certificate = await db.certificates.find_one({"_id": ObjectId(certificate_id)})
    if not certificate:
        raise HTTPException(status_code=404, detail="Certificate not found")
    
    cert_id = str(certificate["_id"])
    
    result = {
        "certificate_id": cert_id,
        "certificate_number": certificate["certificate_id"],
        "license_plate": certificate["license_plate"],
        "valid": True,
        "checks": {}
    }
    
    result["checks"]["status"] = {
        "passed": certificate["status"] not in ["revoked", "stolen", "expired"],
        "value": certificate["status"]
    }
    if not result["checks"]["status"]["passed"]:
        result["valid"] = False
        result["reason"] = f"Certificate status is {certificate['status']}"
    
    valid_until = certificate["valid_until"]
    if isinstance(valid_until, str):
        from dateutil import parser
        valid_until = parser.isoparse(valid_until)
    
    if valid_until.tzinfo is None:
        valid_until = valid_until.replace(tzinfo=timezone.utc)
    
    now = datetime.now(timezone.utc)
    is_expired = valid_until < now
    
    result["checks"]["expiration"] = {
        "passed": not is_expired,
        "valid_from": certificate["valid_from"],
        "valid_until": certificate["valid_until"]
    }
    if is_expired and result["valid"]:
        result["valid"] = False
        result["reason"] = "Certificate has expired"
    
    if check_revocation:
        revoked = await db.certificate_revocations.find_one({
            "certificate_id": cert_id
        })
        result["checks"]["revocation"] = {
            "passed": revoked is None,
            "revoked": revoked is not None
        }
        if revoked and result["valid"]:
            result["valid"] = False
            result["reason"] = f"Certificate was revoked on {revoked.get('revocation_date')}"
    
    cert_path = Path(certificate["certificate_path"])
    crypto_valid = False
    crypto_error = None
    
    if cert_path.exists():
        try:
            crypto_valid = certificate_generator.verify_certificate(cert_path)
        except Exception as e:
            crypto_error = str(e)
    else:
        crypto_error = "Certificate file not found"
    
    result["checks"]["cryptographic"] = {
        "passed": crypto_valid,
        "error": crypto_error
    }
    if not crypto_valid and result["valid"]:
        result["valid"] = False
        result["reason"] = crypto_error or "Cryptographic verification failed"
    
    result["issuer"] = {
        "ca": certificate["issuer_ca"],
        "certificate_id": certificate.get("issuer_certificate_id")
    }
    
    result["algorithm"] = {
        "key": certificate["key_algorithm"],
        "key_size": certificate["key_size"],
        "signature": certificate["signature_algorithm"]
    }
    
    return result

@router.post("/generate-csr")
async def generate_csr(vehicle_data: dict, db=Depends(get_database)):
    try:
        csr_pem, private_key = await certificate_generator.generate_csr(vehicle_data)
        return {
            "csr": csr_pem
        }
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))