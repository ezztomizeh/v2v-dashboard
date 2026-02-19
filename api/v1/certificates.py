from fastapi import APIRouter, Depends, HTTPException, status
from typing import List
from bson import ObjectId
from datetime import datetime, timedelta

from models.certificate import CertificateModel
from config.database import get_database