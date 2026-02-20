from typing import Annotated, Any, Dict, List, Union
from bson import ObjectId
from datetime import datetime
from pydantic import BeforeValidator

def validate_object_id(value: str) -> str:
    if not ObjectId.is_valid(value):
        raise ValueError(f"Invalid ObjectId: {value}")
    return value

def convert_objectid_to_str(doc: Any) -> Any:
    if doc is None:
        return None
    
    if isinstance(doc, ObjectId):
        return str(doc)
    
    if isinstance(doc, datetime):
        return doc.isoformat()
    
    if isinstance(doc, list):
        return [convert_objectid_to_str(item) for item in doc]
    
    if isinstance(doc, dict):
        result = {}
        for key, value in doc.items():
            if key == "_id":
                result["id"] = convert_objectid_to_str(value)
            else:
                result[key] = convert_objectid_to_str(value)
        return result
    
    return doc


def prepare_response(doc: Any) -> Any:
    return convert_objectid_to_str(doc)

PyObjectId = Annotated[str, BeforeValidator(validate_object_id)]