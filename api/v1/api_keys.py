from fastapi import APIRouter, Depends, HTTPException, status
from datetime import datetime, timedelta, timezone
from typing import List
from bson import ObjectId

from models.auth import APIKeyCreate, APIKeyResponse
from core.security import (
    get_current_user, check_permissions, generate_api_key,
    get_password_hash, pwd_context
)
from config.database import get_database
from config.settings import settings
from utils.object_id import convert_objectid_to_str

router = APIRouter(prefix="api-keys",tags=["API Keys"])

@router.get("/", response_model=[APIKeyResponse])
async def list_api_keys(
    db = Depends(get_database),
    current_user: dict = Depends(check_permissions["api_keys:manage"])
):
    cursor = db.api_keys.find().sort("created_at",-1)
    keys = await cursor.to_list(length=100)

    result = []
    for key in keys:
        key["id"] = str(key["_id"])
        key.pop("_id")
        key.pop("key_hash")
        result.append(key)
    
    return result


async def create_api_key(
    key_data: APIKeyCreate,
    db = Depends(get_database),
    current_user = Depends(check_permissions(["api_keys:manage"]))
):
    """
    Create a new API key (admin only)
    """
    # Generate key_id
    key_id = f"{key_data.entity_type}_{key_data.name.lower().replace(' ', '_')}"
    
    # Check if key_id already exists
    existing = await db.api_keys.find_one({"key_id": key_id})
    if existing:
        # Add random suffix
        import random
        key_id = f"{key_id}_{random.randint(1000, 9999)}"
    
    # Generate actual API key
    plain_key = generate_api_key()
    
    # Create document
    key_doc = {
        "key_id": key_id,
        "key_hash": pwd_context.hash(plain_key),
        "name": key_data.name,
        "entity_type": key_data.entity_type,
        "entity_id": key_data.entity_id,
        "permissions": key_data.permissions,
        "ip_whitelist": key_data.ip_whitelist,
        "rate_limit": 1000,
        "expires_at": key_data.expires_at or (datetime.now(timezone.utc) + timedelta(days=settings.api_key_expire_days)),
        "notes": key_data.notes,
        "created_at": datetime.now(timezone.utc),
        "created_by": ObjectId(current_user["id"]),
        "is_active": True
    }
    
    result = await db.api_keys.insert_one(key_doc)
    
    # Return with plain key (only time it's shown)
    key_doc["id"] = str(result.inserted_id)
    key_doc.pop("_id")
    key_doc.pop("key_hash")
    key_doc["plain_key"] = plain_key
    
    return key_doc


@router.get("/{key_id}", response_model=APIKeyResponse)
async def get_api_key(
    key_id: str,
    db = Depends(get_database),
    current_user = Depends(check_permissions(["api_keys:manage"]))
):
    """
    Get API key details (admin only)
    """
    key = await db.api_keys.find_one({"key_id": key_id})
    if not key:
        key = await db.api_keys.find_one({"_id": ObjectId(key_id)})
    
    if not key:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="API key not found"
        )
    
    key["id"] = str(key["_id"])
    key.pop("_id")
    key.pop("key_hash")
    
    return key


@router.delete("/{key_id}")
async def revoke_api_key(
    key_id: str,
    db = Depends(get_database),
    current_user = Depends(check_permissions(["api_keys:manage"]))
):
    """
    Revoke an API key (admin only)
    """
    # Try by key_id first
    result = await db.api_keys.update_one(
        {"key_id": key_id},
        {"$set": {"is_active": False}}
    )
    
    if result.matched_count == 0:
        # Try by ObjectId
        if ObjectId.is_valid(key_id):
            result = await db.api_keys.update_one(
                {"_id": ObjectId(key_id)},
                {"$set": {"is_active": False}}
            )
    
    if result.matched_count == 0:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="API key not found"
        )
    
    return {"message": "API key revoked successfully"}


@router.post("/{key_id}/rotate", response_model=APIKeyResponse)
async def rotate_api_key(
    key_id: str,
    db = Depends(get_database),
    current_user = Depends(check_permissions(["api_keys:manage"]))
):
    key = None
    if ObjectId.is_valid(key_id):
        key = await db.api_keys.find_one({"_id": ObjectId(key_id)})
    
    if not key:
        key = await db.api_keys.find_one({"key_id": key_id})
    
    if not key:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="API key not found"
        )
    
    plain_key = generate_api_key()
    
    await db.api_keys.update_one(
        {"_id": key["_id"]},
        {
            "$set": {
                "key_hash": pwd_context.hash(plain_key),
                "updated_at": datetime.now(timezone.utc)
            }
        }
    )
    
    key["id"] = str(key["_id"])
    key.pop("_id")
    key.pop("key_hash")
    key["plain_key"] = plain_key
    
    return key
