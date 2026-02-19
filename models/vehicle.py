from datetime import datetime
from typing import Optional
from pydantic import BaseModel, Field, ConfigDict, EmailStr
from utils.object_id import PyObjectId

class OwnerModel(BaseModel):
    full_name: str = Field(..., description="Full name of the vehicle owner")
    national_id: str = Field(..., description="National ID or passport number")
    phone: str = Field(..., description="Contact phone number with country code")
    email: EmailStr = Field(..., description="Email address")
    address: dict = Field(default_factory=dict, description="Physical address details")

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
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
            }
        }
    )

class HardwareModel(BaseModel):
    obu_id: str = Field(..., description="Unique ESP32 identifier for the On-Board Unit")
    firmware_version: str = Field(..., description="Current firmware version of the OBU")
    last_communication: Optional[datetime] = Field(None, description="Timestamp of last communication with RSU")
    last_location: Optional[dict] = Field(None, description="Last known GPS coordinates {latitude, longitude}")

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "obu_id": "OBU123456",
                "firmware_version": "1.0.0",
                "last_communication": "2024-01-01T12:00:00Z",
                "last_location": {
                    "latitude": 40.7128,
                    "longitude": -74.0060
                }
            }
        }
    )

class VehicleBase(BaseModel):
    """Base vehicle model with common fields"""
    license_plate: str = Field(..., description="Vehicle license plate number", min_length=3, max_length=20)
    chassis_number: str = Field(..., description="Vehicle chassis/VIN number", min_length=10, max_length=30)
    registration_number: str = Field(..., description="Government registration number")
    
    # Vehicle specifications
    vehicle_type: str = Field(..., description="Type of vehicle (sedan, SUV, truck, motorcycle, bus, emergency)")
    manufacturer: str = Field(..., description="Vehicle manufacturer")
    model: str = Field(..., description="Vehicle model name")
    manufacturer_year: int = Field(..., description="Year of manufacture", ge=1900, le=datetime.now().year)
    color: str = Field(..., description="Vehicle color")
    engine_capacity: str = Field(..., description="Engine capacity (e.g., '2.5L', '2000cc', 'Electric')")
    fuel_type: str = Field(..., description="Fuel type (petrol, diesel, electric, hybrid)")

class VehicleModel(VehicleBase):
    """Complete vehicle document model matching MongoDB collection"""
    id: Optional[PyObjectId] = Field(alias="_id", default=None, description="MongoDB document ID")
    
    # Owner information
    owner: OwnerModel = Field(..., description="Vehicle owner information")
    
    # Hardware information
    hardware: HardwareModel = Field(..., description="Hardware configuration")
    
    # System fields
    is_active: bool = Field(True, description="Whether vehicle is active in the system")
    registered_at: datetime = Field(default_factory=datetime.now, description="Registration date in system")
    registration_expiry: Optional[datetime] = Field(None, description="Registration expiry date")
    
    # Audit
    created_at: datetime = Field(default_factory=datetime.now, description="Creation timestamp")
    updated_at: datetime = Field(default_factory=datetime.now, description="Last update timestamp")
    created_by: Optional[str] = Field(None, description="Username who created this record")
    notes: Optional[str] = Field(None, description="Additional notes about the vehicle")

    model_config = ConfigDict(
        populate_by_name=True,
        arbitrary_types_allowed=True,
        json_schema_extra={
            "example": {
                "id": "67b5a8c1f1a2b3c4d5e6f7g8",
                "license_plate": "ABC-1234",
                "chassis_number": "1HGCM82633A004352",
                "registration_number": "REG123456",
                "vehicle_type": "Sedan",
                "manufacturer": "Toyota",
                "model": "Camry",
                "manufacturer_year": 2020,
                "color": "Blue",
                "engine_capacity": "2.5L",
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
                "notes": "VIP vehicle - priority handling"
            }
        }
    )

class VehicleCreateModel(VehicleBase):
    """Model for creating a new vehicle - without system fields"""
    owner: OwnerModel = Field(..., description="Vehicle owner information")
    hardware: HardwareModel = Field(..., description="Hardware configuration")
    registration_expiry: Optional[datetime] = Field(None, description="Registration expiry date")

    model_config = ConfigDict(
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
                "engine_capacity": "2.5L",
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
                    "last_location": {
                        "latitude": 40.7128,
                        "longitude": -74.0060
                    }
                },
                "registration_expiry": "2025-01-01T12:00:00Z"
            }
        }
    )

class VehicleUpdateModel(BaseModel):
    """Model for updating a vehicle - all fields optional"""
    license_plate: Optional[str] = Field(None, description="Vehicle license plate number")
    chassis_number: Optional[str] = Field(None, description="Vehicle chassis/VIN number")
    registration_number: Optional[str] = Field(None, description="Government registration number")
    
    # Vehicle specifications
    vehicle_type: Optional[str] = Field(None, description="Type of vehicle")
    manufacturer: Optional[str] = Field(None, description="Vehicle manufacturer")
    model: Optional[str] = Field(None, description="Vehicle model name")
    manufacturer_year: Optional[int] = Field(None, description="Year of manufacture", ge=1900, le=datetime.now().year)
    color: Optional[str] = Field(None, description="Vehicle color")
    engine_capacity: Optional[str] = Field(None, description="Engine capacity")
    fuel_type: Optional[str] = Field(None, description="Fuel type")
    
    # Owner information
    owner: Optional[OwnerModel] = Field(None, description="Vehicle owner information")
    
    # Hardware information
    hardware: Optional[HardwareModel] = Field(None, description="Hardware configuration")
    
    # System fields
    is_active: Optional[bool] = Field(None, description="Whether vehicle is active in system")
    registration_expiry: Optional[datetime] = Field(None, description="Registration expiry date")
    
    # Audit
    updated_at: datetime = Field(default_factory=datetime.now, description="Last update timestamp")
    updated_by: Optional[str] = Field(None, description="Username who updated this record")
    notes: Optional[str] = Field(None, description="Additional notes about the vehicle")

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "color": "Black",
                "is_active": True,
                "notes": "Vehicle color updated",
                "updated_by": "admin"
            }
        }
    )