from fastapi import FastAPI, Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from config.database import connect_to_mongodb, close_mongodb_connection
from api.v1 import vehicles
from contextlib import asynccontextmanager

@asynccontextmanager
async def lifespan(app: FastAPI):
    await connect_to_mongodb()
    print("🚀 V2V Dashboard API starting up...")
    
    yield

    await close_mongodb_connection()
    print("🚀 V2V Dashboard API shutting down...")

app = FastAPI(
    title="V2V Dashboard API",
    description="API for managing vehicles in the V2V Dashboard",
    version="1.0.0",
    lifespan=lifespan
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(vehicles.router, prefix="/api/v1", tags=["Vehicles"])

@app.get("/")
async def root():
    return {
        "message": "V2V Secure Communication Dashboard API",
        "version": "1.0.0",
        "docs": "/docs"
    }
