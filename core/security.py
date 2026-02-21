from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Any, List
import uuid
import secrets
import string

from jose import JWTError, jwt
from passlib.context import CryptContext
from fastapi import HTTPException, Depends, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials, APIKeyHeader
from bson import ObjectId

from config.settings import settings
from config.database import get_database

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

security = HTTPBearer()
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password,hashed_password)

def validate_password_strength(password: str) -> tuple[bool, str]:
    if len(password) < settings.password_min_length:
        return False, f"Password must be at least {settings.password_min_length} characters"
    
    if settings.password_require_uppercase and not any(c.isupper() for c in password):
        return False, "Password must contain at least one uppercase letter"
    
    if settings.password_require_lowercase and not any(c.islower() for c in password):
        return False, "Password must contain at least one lowercase letter"
    
    if settings.password_require_numbers and not any(c.isdigit() for c in password):
        return False, "Password must contain at least one number"
    
    if settings.password_require_special and not any(c in string.punctuation for c in password):
        return False, "Password must contain at least one special character"
    
    return True, "Password is valid"

def create_access_token(data: Dict[str, Any], session_id: str) -> str:
    to_encode = data.copy()

    now = datetime.now(timezone.utc)
    token_id = str(uuid.uuid4())

    to_encode.update({
        "type":"access",
        "session_id": session_id,
        "jti": token_id,
        "iat": now,
        "exp": now + timedelta(minutes=settings.access_token_expire_minutes),
        "iss":"v2v-dashboard"
    })

    return jwt.encode(to_encode, settings.secret_key, settings.algorithm)

def create_refresh_token(user_id: str, session_id: str) -> str:
    now = datetime.now(timezone.utc)
    token_id = str(uuid.uuid4())

    payload = {
        "sub": str(user_id),
        "type": "refresh",
        "session_id": session_id,
        "jti": token_id,
        "iat": now,
        "exp": now + timedelta(days=settings.refresh_token_expire_days),
        "iss":"v2v-dashboard"
    }

    return jwt.encode(payload,settings.secret_key,settings.algorithm)

def generate_api_key() -> str:
    random_part = secrets.token_hex(16)
    return f"{settings.api_key_prefix}{random_part}"

async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db = Depends(get_database)):

    token = credentials.credentials

    try:
        payload = jwt.decode(token, settings.secret_key, settings.algorithm)
        if payload.get("type") != "access":
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                                detail="Invalid Token Type")
        
        user_id = payload.get("sub")
        session_id = payload.get("session_id")
        token_id = payload.get("jti")

        if not user_id or not session_id or not token_id:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                                detail="Invalid Token Claim")
        
        revoked = await db.revoked_tokens.find_one({"jwt_id": token_id})
        if revoked:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                                detail="Token Has Been Revoked")
        
        session = await db.sessions.find_one({
            "session_id": session_id,
            "is_revoked": False
        })
        if not session:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                                detail="Session not found or revoked")
        
        user = db.users.find_one({
            "_id": ObjectId(user_id)
        })

        if not user or user.get("is_active", False):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                                detail="User not found or inactive")
        
        await db.sessions.update_one(
            {"session_id":session_id},
            {"$set": {"last_activity": datetime.now(timezone.utc)}}
            )
        
        user["id"] = str(user["_id"])
        user.pop("_id")
        user.pop("password_hash", None)
        
        return user
    except:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="Could not validate credentials")
    

async def get_current_api_key(
        api_key: str = Depends(api_key_header),
        db = Depends(get_database)):
    
    if not api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="API Key Required"
        )

    key_data = db.api_keys.find_one({"is_active":True})
    cursor = db.api_key.find({"is_active":True})
    async for key_doc in cursor:
        if pwd_context.verify(api_key, key_doc["key_hash"]):
            if key_doc.get("expires_at") and key_doc.get(
                "expires_at") < datetime.now(timezone.utc):
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                                    detail="API Key Has Expired")
            
            await db.api_key.update_one(
                {"_id":key_doc["_id"]},
                {"$set":
                 {
                     "last_used":datetime.now(timezone.utc),
                     "last_used_ip":"NaN"
                 }
                }
            )

            key_doc["id"] = str(key_doc["_id"])
            key_doc["_id"].pop()
            key_doc["key_hash"].pop()

            return key_doc
    raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                        detail="Invalid API Key")


def check_premissions(required_premissions: List[str]):
    async def permission_checker(current_user: dict = Depends(get_current_user)):
        
        user_premissions = current_user.get("premissions",[])
        for perm in required_premissions:
            if perm not in user_premissions:
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                                    detail=f"Missing required permission: {perm}")
        return current_user
    return permission_checker

def check_role(allowed_roles: List[str]):
    async def role_checker(current_user = Depends(get_current_user)):
        if current_user.get("role") not in allowed_roles:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                                detail=f"Role Not Allowed. Required {allowed_roles}")
        return current_user
    return role_checker