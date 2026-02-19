from datetime import datetime
from typing import Optional
from pydantic import BaseModel, Field, ConfigDict, EmailStr
from utils.object_id import PyObjectId

class OwnerModel(BaseModel):
    full_name: str = Field(..., description="Ezzudin Tomizi")
    national_id: str = Field(..., description="1234567890")
    phone: str = Field(..., description="+1234567890")
    email: EmailStr
    address: dict = Field(default_factory=dict)


class HardwareModel(BaseModel):
    obu_id: str = Field(..., description="OBU123456")
    firmware_version: str = Field(..., description="1.0.0")
    last_communication: Optional[datetime] = Field(None, description="2024-01-01T12:00:00Z")
    last_location: Optional[dict] = Field(None, description={"latitude": 40.7128, "longitude": -74.0060})

class VehicleModel(BaseModel):
    obu_id: Optional[PyObjectId] = Field(alias="_id", default=None)
    license_plate: str = Field(..., description="ABC-1234")
    chassis_number: str = Field(..., description="1HGCM82633A004352")
    registration_number: str = Field(..., description="REG123456")

    # Vehicle specifications
    vehicle_type: str = Field(..., description="Sedan")
    manufacturer: str = Field(..., description="Toyota")
    model: str = Field(..., description="Camry")
    manufacturer_year: int = Field(..., description=2020)
    color: str = Field(..., description="Blue")
    engine_capacity: int = Field(..., description=2500)
    fuel_type: str = Field(..., description="Gasoline")

    # Onwer information
    owner: OwnerModel

    # Hardware information
    hardware: HardwareModel

    # System fields
    is_active: bool = True
    registered_at: datetime = Field(default_factory=datetime.now())
    registration_expiry: Optional[datetime] = Field(None, description="2025-01-01T12:00:00Z")

    # Audit
    created_at: datetime = Field(default_factory=datetime.now())
    updated_at: datetime = Field(default_factory=datetime.now())
    created_by: Optional[str] = Field(None, description="admin")
    notes: Optional[str] = Field(None, description="Additional notes about the vehicle")

    model_config = ConfigDict(
        populate_by_name=True,
        arbitrary_types_allowed=True,
        json_schema_extra={
            "example": {
                "license_plate": "ABC-1234",
                "chassis_number": "1HGCM82633A004352",
                "registration_number": "REG123456",
                "vehicle_type": "Sedan",
                "manufacturer": "Toyota",
                "model": "Camry",
                "manufacturer_year": 2020,
                "color": "Blue",
                "engine_capacity": 2500,
                "fuel_type": "Gasoline",
                "owner": {
                    "full_name": "Ezzudin Tomizi",
                    "national_id": "1234567890",
                    "phone": "+1234567890",
                    "email": "ezz@ezz.com",
                    "address": {
                        "street": "123 Main St",
                        "city": "Anytown",
                        "state": "CA",
                        "zip": "12345"
                    }
                },
                "hardware": {
                    "obu_id": "OBU123456",
                    "firmware_version": "1.0.0",
                    "last_communication": "2024-01-01T12:00:00Z",
                    "last_location": {
                        "latitude": 40.7128,
                        "longitude": -74.0060
                    }
                },
                "is_active": True,
                "registered_at": "2024-01-01T12:00:00Z",
                "registration_expiry": "2025-01-01T12:00:00Z",
                "created_at": "2024-01-01T12:00:00Z",
                "updated_at": "2024-01-01T12:00:00Z",
                "created_by": "admin",
                "notes": "Additional notes about the vehicle"
            }
        }
    )

class vehicleCreateModel(BaseModel):
    license_plate: str = Field(..., description="ABC-1234")
    chassis_number: str = Field(..., description="1HGCM82633A004352")
    registration_number: str = Field(..., description="REG123456")

    # Vehicle specifications
    vehicle_type: str = Field(..., description="Sedan")
    manufacturer: str = Field(..., description="Toyota")
    model: str = Field(..., description="Camry")
    manufacturer_year: int = Field(..., description=2020)
    color: str = Field(..., description="Blue")
    engine_capacity: int = Field(..., description=2500)
    fuel_type: str = Field(..., description="Gasoline")

    # Onwer information
    owner: OwnerModel

    # Hardware information
    hardware: HardwareModel

class VehicleUpdateModel(BaseModel):
    license_plate: Optional[str] = Field(None, description="ABC-1234")
    chassis_number: Optional[str] = Field(None, description="1HGCM82633A004352")
    registration_number: Optional[str] = Field(None, description="REG123456")

    # Vehicle specifications
    vehicle_type: Optional[str] = Field(None, description="Sedan")
    manufacturer: Optional[str] = Field(None, description="Toyota")
    model: Optional[str] = Field(None, description="Camry")
    manufacturer_year: Optional[int] = Field(None, description=2020)
    color: Optional[str] = Field(None, description="Blue")
    engine_capacity: Optional[int] = Field(None, description=2500)
    fuel_type: Optional[str] = Field(None, description="Gasoline")

    # Onwer information
    owner: Optional[OwnerModel]

    # Hardware information
    hardware: Optional[HardwareModel]

    # System fields
    is_active: Optional[bool] = None
    registration_expiry: Optional[datetime] = Field(None, description="2025-01-01T12:00:00Z")

    # Audit
    updated_at: datetime = Field(default_factory=datetime.now())
    updated_by: Optional[str] = Field(None, description="admin")
    notes: Optional[str] = Field(None, description="Additional notes about the vehicle")

