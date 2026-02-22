from fastapi import APIRouter, HTTPException, Depends, status
from datetime import datetime, timezone
from typing import List
from bson import ObjectId

from models.auth import UserCreate, UserUpdate, UserResponse
from core.security import (
    get_password_hash, validate_password_strength,
    get_current_user, check_permissions, check_role
)
from config.database import get_database
from utils.object_id import convert_objectid_to_str

router = APIRouter(prefix="/users", tags=["Users"])


@router.get("/", response_model=List[UserResponse])
async def list_users(
    db = Depends(get_database),
    current_user = Depends(check_permissions(["users:manage"]))
):
    """
    List all users (admin only)
    """
    cursor = db.users.find().sort("created_at", -1)
    users = await cursor.to_list(length=100)
    
    result = []
    for user in users:
        user["id"] = str(user["_id"])
        user.pop("_id")
        user.pop("password_hash")
        user.pop("failed_login_attempts", None)
        user.pop("locked_until", None)
        result.append(user)
    
    return result


@router.post("/", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def create_user(
    user_data: UserCreate,
    db = Depends(get_database),
    current_user = Depends(check_permissions(["users:manage"]))
):
    """
    Create a new user (admin only)
    """
    # Check if username exists
    existing = await db.users.find_one({
        "$or": [
            {"username": user_data.username},
            {"email": user_data.email}
        ]
    })
    
    if existing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username or email already exists"
        )
    
    # Validate password strength
    is_valid, message = validate_password_strength(user_data.password)
    if not is_valid:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=message
        )
    
    # Set default permissions based on role
    role_permissions = {
        "admin": [
            "vehicle:create", "vehicle:read", "vehicle:update", "vehicle:delete",
            "certificate:issue", "certificate:revoke", "certificate:verify",
            "certificate:mark_stolen", "certificate:check_revocation",
            "users:manage", "audit:view", "api_keys:manage"
        ],
        "operator": [
            "vehicle:create", "vehicle:read", "vehicle:update",
            "certificate:issue", "certificate:revoke", "certificate:verify",
            "certificate:check_revocation"
        ],
        "viewer": [
            "vehicle:read", "certificate:verify", "certificate:check_revocation"
        ],
        "law_enforcement": [
            "vehicle:read", "certificate:verify", "certificate:check_revocation",
            "certificate:mark_stolen", "audit:view"
        ]
    }
    
    permissions = user_data.permissions or role_permissions.get(user_data.role, [])
    
    # Create user document
    user_doc = {
        "username": user_data.username,
        "email": user_data.email,
        "full_name": user_data.full_name,
        "password_hash": get_password_hash(user_data.password),
        "role": user_data.role,
        "permissions": permissions,
        "department": user_data.department,
        "phone": user_data.phone,
        "is_active": True,
        "failed_login_attempts": 0,
        "locked_until": None,
        "password_changed_at": datetime.now(timezone.utc),
        "created_at": datetime.now(timezone.utc),
        "created_by": ObjectId(current_user["id"]),
        "updated_at": datetime.now(timezone.utc)
    }
    
    result = await db.users.insert_one(user_doc)
    
    # Return created user
    user_doc["id"] = str(result.inserted_id)
    user_doc.pop("_id")
    user_doc.pop("password_hash")
    
    return user_doc


@router.get("/{user_id}", response_model=UserResponse)
async def get_user(
    user_id: str,
    db = Depends(get_database),
    current_user = Depends(get_current_user)
):
    """
    Get user by ID (admin only, or self)
    """
    if not ObjectId.is_valid(user_id):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid user ID"
        )
    
    # Check if user is accessing their own data or is admin
    if str(current_user["id"]) != user_id and "users:manage" not in current_user.get("permissions", []):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to view this user"
        )
    
    user = await db.users.find_one({"_id": ObjectId(user_id)})
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    user["id"] = str(user["_id"])
    user.pop("_id")
    user.pop("password_hash")
    
    return user


@router.put("/{user_id}", response_model=UserResponse)
async def update_user(
    user_id: str,
    user_data: UserUpdate,
    db = Depends(get_database),
    current_user = Depends(get_current_user)
):
    """
    Update user (admin only, or self for limited fields)
    """
    if not ObjectId.is_valid(user_id):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid user ID"
        )
    
    # Check permissions
    is_self = str(current_user["id"]) == user_id
    is_admin = "users:manage" in current_user.get("permissions", [])
    
    if not is_self and not is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to update this user"
        )
    
    # Build update data
    update_data = {k: v for k, v in user_data.model_dump().items() if v is not None}
    
    # Self can only update limited fields
    if is_self and not is_admin:
        allowed_fields = ["full_name", "phone", "department"]
        update_data = {k: v for k, v in update_data.items() if k in allowed_fields}
    
    if not update_data:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No fields to update"
        )
    
    update_data["updated_at"] = datetime.now(timezone.utc)
    
    # Update user
    result = await db.users.update_one(
        {"_id": ObjectId(user_id)},
        {"$set": update_data}
    )
    
    if result.matched_count == 0:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    # Return updated user
    user = await db.users.find_one({"_id": ObjectId(user_id)})
    user["id"] = str(user["_id"])
    user.pop("_id")
    user.pop("password_hash")
    
    return user


@router.delete("/{user_id}")
async def delete_user(
    user_id: str,
    db = Depends(get_database),
    current_user = Depends(check_permissions(["users:manage"]))
):
    """
    Delete/deactivate user (admin only)
    """
    if not ObjectId.is_valid(user_id):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid user ID"
        )
    
    # Don't allow deleting yourself
    if str(current_user["id"]) == user_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot delete your own account"
        )
    
    # Soft delete (deactivate)
    result = await db.users.update_one(
        {"_id": ObjectId(user_id)},
        {
            "$set": {
                "is_active": False,
                "updated_at": datetime.now(timezone.utc)
            }
        }
    )
    
    if result.matched_count == 0:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    # Revoke all sessions
    await db.sessions.update_many(
        {"user_id": ObjectId(user_id)},
        {"$set": {"is_revoked": True, "revoked_reason": "user_deleted"}}
    )
    
    return {"message": "User deactivated successfully"}


@router.post("/{user_id}/reset-password")
async def admin_reset_password(
    user_id: str,
    new_password: str,
    db = Depends(get_database),
    current_user = Depends(check_permissions(["users:manage"]))
):
    """
    Admin force reset user password (admin only)
    """
    if not ObjectId.is_valid(user_id):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid user ID"
        )
    
    # Validate password strength
    is_valid, message = validate_password_strength(new_password)
    if not is_valid:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=message
        )
    
    # Update password
    result = await db.users.update_one(
        {"_id": ObjectId(user_id)},
        {
            "$set": {
                "password_hash": get_password_hash(new_password),
                "password_changed_at": datetime.now(timezone.utc),
                "failed_login_attempts": 0,
                "locked_until": None,
                "updated_at": datetime.now(timezone.utc)
            }
        }
    )
    
    if result.matched_count == 0:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    # Revoke all sessions for security
    await db.sessions.update_many(
        {"user_id": ObjectId(user_id)},
        {"$set": {"is_revoked": True, "revoked_reason": "admin_password_reset"}}
    )
    
    return {"message": "Password reset successfully"}