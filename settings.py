from functools import lru_cache
from pydantic import BaseSettings

class Settings(BaseSettings):
    access_token_expire_minues: int
    secret_key: str
    algorithm: str

    class Config:
        env_file = '.env'

@lru_cache()
def get_settings():
    return Settings()
