from pydantic_settings import BaseSettings
from dotenv import load_dotenv

load_dotenv()

class Settings(BaseSettings):

    #MongoDB configuration
    mongodb_url: str = "mongodb://localhost:27017"
    database_name: str = "v2v_dashboard"

    # Security configuration
    secret_key: str = "G7#kP2@zR9!mX4$wT6&cV1*eL8^nQ3%"
    algorithm: str = "HS256"
    access_token_expire_minutes: int = 30

    # Cerfificate configuration
    cert_public_key_path: str = "certs/"
    cert_cerificate_path: str = "certs/certs/"

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"

settings = Settings()