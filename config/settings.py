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

    # Cerfificate configuration
    # Certificate paths
    BASE_DIR: Path = Path(__file__).parent.parent.parent
    CERTS_BASE_DIR: Path = BASE_DIR / "certs"
    
    CA_CERT_PATH: str = str(CERTS_BASE_DIR / "ca" / "ca_cert.pem")
    CA_KEY_PATH: str = str(CERTS_BASE_DIR / "ca" / "ca_key.pem")
    CERTIFICATES_PATH: str = str(CERTS_BASE_DIR / "vehicles" / "certs")
    PRIVATE_KEYS_PATH: str = str(CERTS_BASE_DIR / "vehicles" / "private")
    PUBLIC_KEYS_PATH: str = str(CERTS_BASE_DIR / "vehicles" / "public")

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"

settings = Settings()