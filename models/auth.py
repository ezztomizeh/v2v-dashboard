from datetime import datetime
from typing import Optional, List
from pydantic import BaseModel, EmailStr, Field, ConfigDict
from utils.object_id import PyObjectId

class UserBase(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    email: EmailStr
    full_name: str = Field(...,min_length=2, max_length=100)
    role: str = Field("viewer",pattern="^(admin|operator|viewer|law_enforcement)$")
    permissions: List[str] = Field(default_factory=list)
    department: Optional[str] = None
    phone: Optional[str] = None
    is_active: bool = True

class CreateUser(UserBase):
    password: str = Field(...,min_length=8)

class UserUpdate(UserBase):
    full_name: Optional[str] = None
    email: Optional[EmailStr] = None
    department: Optional[str] = None
    phone: Optional[str] = None
    is_active: Optional[bool] = None
    role: Optional[str] = None
    permissions: Optional[List[str]] = None

class UserInDB(UserBase):
    id: Optional[PyObjectId] = Field(alias="_id", default=None)
    password_hash: str
    failed_login_attempts: int = 0
    lockedout_until: Optional[datetime] = None
    last_login: Optional[datetime] = None
    last_login_ip: Optional[str] = None
    password_changed_at: datetime = Field(default_factory=datetime.now)
    created_at: datetime = Field(default_factory=datetime.now)
    created_by: Optional[PyObjectId] = None
    updated_at: datetime = Field(default_factory=datetime.now)

    model_config = ConfigDict(
        populate_by_name=True,
        arbitrary_types_allowed=True
    )

class UserResponse(BaseModel):
    id: str
    username: str
    email: str
    full_name: str
    role: str
    permissions: List[str]
    department: Optional[str]
    phone: Optional[str]
    is_active: bool
    last_login: Optional[datetime]
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)

class LoginRequest(BaseModel):
    username: str
    password: str

class LoginResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int
    user: UserResponse

class RefreshTokenRequest(BaseModel):
    refresh_token: str

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int

class PasswordChangeRequest(BaseModel):
    current_password: str
    new_password: str

class PasswordResetRequest(BaseModel):
    email: EmailStr

class PasswordResetConfirm(BaseModel):
    token: str
    new_password: str

class SessionInfo(BaseModel):
    session_id: str
    device_name: Optional[str]
    ip_address: str
    user_agent: str
    created_at: datetime
    last_activity: datetime
    expires_at: datetime
    is_current: bool = False

class APIKeyBase(BaseModel):
    name: str
    entity_type: str = Field(..., pattern="^(rsu|external_system|script)$")
    entity_id: Optional[str] = None
    permissions: List[str] = Field(default_factory=list)
    ip_whitelist: List[str] = Field(default_factory=list)
    expires_at: Optional[datetime] = None
    notes: Optional[str] = None

class APIKeyCreate(APIKeyBase):
    pass

class APIKeyInDB(APIKeyBase):
    id: Optional[PyObjectId] = Field(alias="_id", default=None)
    key_id: str
    key_hash: str
    rate_limit: int = 1000
    last_used: Optional[datetime] = None
    last_used_ip: Optional[str] = None
    created_at: datetime = Field(default_factory=datetime.now)
    created_by: PyObjectId
    is_active: bool = True

    model_config = ConfigDict(
        populate_by_name=True,
        arbitrary_types_allowed=True
    )

class APIKeyResponse(BaseModel):
    id: str
    key_id: str
    name: str
    entity_type: str
    entity_id: Optional[str]
    permissions: List[str]
    ip_whitelist: List[str]
    rate_limit: int
    last_used: Optional[datetime]
    expires_at: Optional[datetime]
    created_at: datetime
    is_active: bool
    notes: Optional[str]
    # Only shown once when creating
    plain_key: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)