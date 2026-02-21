from pydantic_settings import BaseSettings
from dotenv import load_dotenv
from pathlib import Path

load_dotenv()

class Settings(BaseSettings):

    #MongoDB configuration
    mongodb_url: str = "mongodb://localhost:27017"
    database_name: str = "v2v_dashboard"

    # Security configuration
    secret_key: str = "G7#kP2@zR9!mX4$wT6&cV1*eL8^nQ3%"
    algorithm: str = "HS256"
    access_token_expire_minutes: int = 30
    refresh_token_expire_days: int  = 7

    # Password Policy
    password_min_length: int = 8
    password_require_uppercase: bool = True
    password_require_lowercase: bool = True
    password_require_numbers: bool = True
    password_require_special: bool = True
    max_login_attempts: int  = 5
    lockout_minutes: int = 15

    # API Keys
    api_key_prefix: str = "v2v_system_"
    api_key_expires: int = 365


    # Cerfificate configuration
    BASE_DIR: Path = Path(__file__).parent.parent.parent
    CERTS_BASE_DIR: Path = BASE_DIR / "certs"
    
    CA_CERT_PATH: str = str(CERTS_BASE_DIR / "ca" / "ca_cert.pem")
    CA_KEY_PATH: str = str(CERTS_BASE_DIR / "ca" / "ca_key.pem")
    CERTIFICATES_PATH: str = str(CERTS_BASE_DIR / "vehicles" / "certs")
    PRIVATE_KEYS_PATH: str = str(CERTS_BASE_DIR / "vehicles" / "private")
    PUBLIC_KEYS_PATH: str = str(CERTS_BASE_DIR / "vehicles" / "public")

    # Default Admin 
    default_admin_username: str = "admin"
    default_admin_password: str = "admin123"
    default_admin_email: str = "221006@ppu.edu.ps"
    default_admin_full_name: str = "System Admin"

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"

settings = Settings()