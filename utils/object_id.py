from typing import Annotated
from bson import ObjectId
from pydantic import BeforeValidator

def validate_object_id(value: str) -> str:
    if not ObjectId.is_valid(value):
        raise ValueError(f"Invalid ObjectId: {value}")
    return value

PyObjectId = Annotated[str, BeforeValidator(validate_object_id)]