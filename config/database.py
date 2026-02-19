from motor.motor_asyncio import AsyncIOMotorClient
from config.settings import settings

class MongoDB:
    client: AsyncIOMotorClient = None
    database = None

db = MongoDB()

async def connect_to_mongodb():
    db.client = AsyncIOMotorClient(
        settings.mongodb_url,
        maxPoolSize=50,
        minPoolSize=10,
        maxIdleTimeMS=30000,
        serverSelectionTimeoutMS=5000
    )
    db.database = db.client[settings.database_name]
    try:
        await db.client.admin.command('ping')
        print("Successfully connected to MongoDB")
    except Exception as e:
        print(f"Error connecting to MongoDB: {e}")
        raise e
    
async def close_mongodb_connection():
    if db.client:
        db.client.close()
        print("MongoDB connection closed")

def get_database():
    if db.database is None:
        raise Exception("Database connection is not established")
    return db.database