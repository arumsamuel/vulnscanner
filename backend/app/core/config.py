from pydantic_settings import BaseSettings
from functools import lru_cache

class Settings(BaseSettings):
    APP_NAME: str = "AegisScan"
    VERSION: str = "1.0.0"
    DEBUG: bool = False

    # CORS
    CORS_ORIGINS: list[str] = ["http://localhost:5173", "http://localhost:3000"]

    # Scanner
    DEFAULT_TIMEOUT: int = 10
    MAX_CONCURRENT: int = 20
    REQUEST_DELAY: float = 0.1

    # Wordlists
    SUBDOMAIN_WORDLIST: str = "wordlists/subdomains.txt"
    DIR_WORDLIST: str = "wordlists/dirs.txt"

    class Config:
        env_file = ".env"

@lru_cache()
def get_settings() -> Settings:
    return Settings()
