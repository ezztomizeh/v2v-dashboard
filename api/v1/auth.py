from fastapi import APIRouter, HTTPException, Depends, status, Request
from datetime import datetime, timezone, timedelta
import uuid
from bson import ObjectId
from jose import JWTError, jwt

from models.auth import (
    LoginRequest, LoginResponse, UserResponse, RefreshTokenRequest,
    TokenResponse, PasswordChangeRequest, PasswordResetRequest,
    PasswordResetConfirm, SessionInfo, APIKeyCreate, APIKeyResponse
    )

from core.security import (
    verify_password, get_password_hash, create_access_token,
    create_refresh_token, get_current_user, validate_password_strength,
    generate_api_key, get_current_api_key, check_permissions, check_role
)

from config.database import get_database
from config.settings import settings
from utils.object_id import convert_objectid_to_str

router = APIRouter("/auth",tags="Authentication")

@router.post("/login", response_model=LoginResponse)
async def login(request: Request, login_data: LoginRequest,
                 db = Depends(get_database)):
    
    client_ip = request.client.host if request.client else "unkown"
    user = db.users.find_one({
        "$or":[{
            "username": login_data.username,
            "email": login_data.username
    }]
    })

    if not user:
        await db.login_attempts.insert_one({
            "username": login_data.username,
            "ip_address": client_ip,
            "success": False,
            "failure_reason": "user_not_found",
            "timestamp": datetime.now(timezone.utc)
        })
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="Invalid Username or Password")
    
    if user.get("locked_until") and user["locked_until"] > datetime.now(timezone.utc):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail=f"Account is locked until {user["locked_until"]}")
    
    if not verify_password(login_data.password,user["password_hash"]):
        failed = user.get("failed_login_attempts", 0) + 1
        updated_data = {"failed_login_attempts": failed}

        if failed >= settings.max_login_attempts:
            updated_data["locked_unitl"] = datetime.now(timezone.utc) + timedelta(minutes=settings.lockout_minutes)
        
        await db.login_attempts.insert_one({
            "username": login_data.username,
            "ip_address": client_ip,
            "success": False,
            "failure_reason": "invalid_password",
            "timestamp": datetime.now(timezone.utc)
        })

        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="Invalid Username or Password")
    
    if not user.get("is_active", True):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="Account is disabled")
    
    await db.users.update_one(
        {"_id": user["_id"]},
        {
            "$set": {
                "failed_login_attempts": 0,
                "locked_until": None,
                "last_login": datetime.now(timezone.utc),
                "last_login_ip": client_ip
            }
        }
    )

    session_id = str(uuid.uuid4())
    await db.sessions.insert_one({
        "session_id": session_id,
        "user_id": user["_id"],
        "username": user["username"],
        "role": user["role"],
        "ip_address": client_ip,
        "user_agent": request.headers.get("user-agent", ""),
        "device_name": f"Login from {client_ip}",
        "created_at": datetime.now(timezone.utc),
        "last_activity": datetime.now(timezone.utc),
        "expires_at": datetime.now(timezone.utc) + timedelta(minutes=settings.access_token_expire_minutes),
        "refresh_expires_at": datetime.now(timezone.utc) + timedelta(days=settings.refresh_token_expire_days),
        "is_revoked": False
    })
    
    await db.login_attempts.insert_one({
        "username": user["username"],
        "ip_address": client_ip,
        "success": True,
        "failure_reason": None,
        "timestamp": datetime.now(timezone.utc)
    })
    
    access_token = create_access_token(
        {
            "sub": str(user["_id"]),
            "username": user["username"],
            "role": user["role"],
            "permissions": user.get("permissions", [])
        },
        session_id
    )
    
    refresh_token = create_refresh_token(str(user["_id"]), session_id)
    
    user_response = {
        "id": str(user["_id"]),
        "username": user["username"],
        "email": user["email"],
        "full_name": user["full_name"],
        "role": user["role"],
        "permissions": user.get("permissions", []),
        "department": user.get("department"),
        "phone": user.get("phone"),
        "is_active": user["is_active"],
        "last_login": user.get("last_login"),
        "created_at": user["created_at"]
    }
    
    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
        "expires_in": settings.access_token_expire_minutes * 60,
        "user": user_response
    }

@router.post('/refresh', response_model=TokenResponse)
async def refresh_token(
    request: RefreshTokenRequest,
    db = Depends(get_database)
):
    try:
        payload = jwt.encode(
            request.refresh_token,
            settings.secret_key,
            algorithm=[settings.algorithm]
        )

        if payload.get("type") != "refresh":
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                                detail="Invalid Token Type")
        
        user_id = payload.get("sub")
        session_id = payload.get("session_id")
        token_id = payload.get("jti")

        if not user_id or not session_id:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token claims"
            )
        
        session = await db.sessions.find_one({
            "session_id": session_id,
            "is_revoked": False,
            "refresh_expires_at": {"$gt": datetime.now(timezone.utc)}
        })

        if not session:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Session not found or expired"
            )
        
        user = await db.users.find_one({"_id": ObjectId(user_id)})
        if not user or not user.get("is_active"):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User not found or inactive"
            )
        
        access_token = create_access_token(
            {
                "sub": str(user["_id"]),
                "username": user["username"],
                "role": user["role"],
                "permissions": user.get("permissions", [])
            },
            session_id
        )

        await db.sessions.update_one(
            {"session_id": session_id},
            {
                "$set": {
                    "expires_at": datetime.now(timezone.utc) + timedelta(minutes=settings.access_token_expire_minutes),
                    "last_activity": datetime.now(timezone.utc)
                }
            }
        )
        
        return {
            "access_token": access_token,
            "token_type": "bearer",
            "expires_in": settings.access_token_expire_minutes * 60
        }
    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="Invalid refresh token")
    

@router.post("/logout")
async def logout(
    request: Request,
    current_user: dict = Depends(get_current_user),
    db = Depends(get_database)):

    auth_header = request.headers.get("authorization","")
    token = auth_header.replace("Bearer","")

    if token:
        try:
            payload  = jwt.decode(token, settings.secret_key, settings.algorithm)
            token_id = payload.get("jti")
            session_id = payload.get("session_id")

            if token_id:
                await db.revoked_tokens.insert_one({
                    "jwt_id": token_id,
                    "session_id": session_id,
                    "user_id": ObjectId(current_user["id"]),
                    "revoked_at": datetime.now(timezone.utc),
                    "revoked_reason": "logout",
                    "expires_at": datetime.now(timezone.utc) + timedelta(days=1)
                })
            
            if session_id:
                await db.sessions.update_one(
                    {"session_id":session_id},
                    {"$set":{
                            "is_revoked": True,
                            "revoked_at": datetime.now(timezone.utc),
                            "revoked_reason": "logout"
                    }}
                )
        except:
            pass


@router.get("/me",response_model=UserResponse)
async def get_current_user_info(
    current_user: dict = Depends(get_current_user)
):
    return current_user

@router.post("/change-password")
async def change_password(
    request: PasswordChangeRequest,
    current_user: dict = Depends(get_current_user),
    db = Depends(get_database)
):
    user = await db.users.find_one({"_id":ObjectId(current_user["id"])})

    if not verify_password(request.current_password, user["password_hash"]):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                            detail="Current Password Is Incorrect")
    
    is_valid, message = validate_password_strength(request.new_password)
    if not is_valid:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                            detail=message)
    
    await db.users.update_one(
        {"_id":ObjectId(current_user["id"])},
        {
            "$set":{
                "password_hash": get_password_hash(request.new_password),
                "password_changed_at": datetime.now(timezone.utc),
                "updated_at": datetime.now(timezone.utc)
            }
        }
    )

@router.get("/sessions", response_model=list[SessionInfo])
async def get_active_sessions(
    request: Request,
    current_user: dict = Depends(get_current_user),
    db = Depends(get_database)
):
    current_user_id = None
    auth_header = request.headers.get("authorization","")
    token = auth_header.replace("Bearer","")

    try:
        payload = jwt.decode(token,settings.secret_key, settings.algorithm)
        current_session_id = payload.get("session_id")
    except:
        pass

    sessions = db.sessions.find({
        "user_id": ObjectId(current_user["id"]),
        "is_revoked": False,
        "expires_at":{"$gt":datetime.now(timezone.utc)}
    }).sort("created_at",-1).to_list(length=100)

    result = []

    for session in sessions:
        result.append({
            "session_id": session["session_id"],
            "device_name": session.get("device_name", "Unknown"),
            "ip_address": session["ip_address"],
            "user_agent": session["user_agent"],
            "created_at": session["created_at"],
            "last_activity": session["last_activity"],
            "expires_at": session["expires_at"],
            "is_current": session["session_id"] == current_session_id
        })

    return result