from fastapi import APIRouter, HTTPException, Depends, status
from typing import List
from bson import ObjectId
from datetime import datetime

from models.vehicle import VehicleModel, VehicleCreateModel, VehicleUpdateModel
from config.database import get_database
from utils.object_id import PyObjectId

router = APIRouter(prefix="/vehicles", tags=["Vehicles"])

@router.post("/", response_model=VehicleModel, status_code=status.HTTP_201_CREATED)
async def create_vehicle(vehicle: VehicleCreateModel, db=Depends(get_database)):
    existing =  await db.vehicles.find_one({
        "$or": [
            {"license_plate": vehicle.license_plate},
            {"chassis_number": vehicle.chassis_number},
            {"registration_number": vehicle.registration_number}]
        })
    if existing:
        raise HTTPException(status_code=400, detail="Vehicle already exists")
    vehicle_dect = vehicle.model_dump()
    vehicle_dect["created_at"] = datetime.now()
    vehicle_dect["updated_at"] = datetime.now()
    vehicle_dect["is_active"] = True
    vehicle_dect["created_by"] = "ezzudin"  # Placeholder for user ID
    result = await db.vehicles.insert_one(vehicle_dect)


    created_vehicle = await db.vehicles.find_one({"_id": result.inserted_id})
    created_vehicle["_id"] = str(created_vehicle.pop("_id"))
    if not created_vehicle:
        raise HTTPException(status_code=500, detail="Failed to create vehicle")
    
    if "owner" in created_vehicle and "_id" in created_vehicle["owner"]:
        created_vehicle["owner"]["id"] = str(created_vehicle["owner"].pop("_id"))
    
    if "hardware" in created_vehicle and "_id" in created_vehicle["hardware"]:
        created_vehicle["hardware"]["id"] = str(created_vehicle["hardware"].pop("_id"))

    return created_vehicle

@router.get("/", response_model=List[VehicleModel])
async def list_vehicles(skip: int = 0, limit: int = 100, db=Depends(get_database)):
    cursor = db.vehicles.find().skip(skip).limit(limit)
    vehicles = await cursor.to_list(length=limit)
    for vehicle in vehicles:
        vehicle["_id"] = str(vehicle["_id"])
    return vehicles

@router.get("/{vehicle_id}", response_model=VehicleModel)
async def get_vehicle(vehicle_id: str, db=Depends(get_database)):
    if not ObjectId.is_valid(vehicle_id):
        raise HTTPException(status_code=400, detail="Invalid vehicle ID")
    vehicle = await db.vehicles.find_one({"_id": ObjectId(vehicle_id)})
    if not vehicle:
        raise HTTPException(status_code=404, detail="Vehicle not found")
    vehicle["_id"] = str(vehicle.pop("_id"))
    return vehicle

@router.put("/{vehicle_id}", response_model=VehicleModel)
async def update_vehicle(vehicle_id: str, vehicle_update: VehicleUpdateModel, db=Depends(get_database)):
    if not ObjectId.is_valid(vehicle_id):
        raise HTTPException(status_code=400, detail="Invalid vehicle ID")
    existing = await db.vehicles.find_one({"_id": ObjectId(vehicle_id)})
    if not existing:
        raise HTTPException(status_code=404, detail="Vehicle not found")
    update_data = {k: v for k, v in vehicle_update.model_dump().items() if v is not None}
    if not update_data:
        raise HTTPException(status_code=400, detail="No valid fields to update")
    update_data["updated_at"] = datetime.now()
    result = await db.vehicles.update_one({"_id": ObjectId(vehicle_id)}, {"$set": update_data})
    if result.modified_count == 0 and result.matched_count == 0:
        raise HTTPException(status_code=404, detail="Vehicle not found")
    
    updated_vehicle = await db.vehicles.find_one({"_id": ObjectId(vehicle_id)})
    updated_vehicle["_id"] = str(updated_vehicle.pop("_id"))
    return updated_vehicle

@router.delete("/{vehicle_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_vehicle(vehicle_id: str, db=Depends(get_database)):
    if not ObjectId.is_valid(vehicle_id):
        raise HTTPException(status_code=400, detail="Invalid vehicle ID")
    result = await db.vehicles.update_one({"_id": ObjectId(vehicle_id)}, {"$set": {"is_active": False, "updated_at": datetime.now()}})
    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="Vehicle not found")
    return None
    