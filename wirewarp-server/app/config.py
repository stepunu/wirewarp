from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    DATABASE_URL: str = "postgresql+asyncpg://wirewarp:secret@db:5432/wirewarp"
    SECRET_KEY: str = "change-me-in-production"
    AGENT_TOKEN_EXPIRY_HOURS: int = 24
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24  # 24 hours

    model_config = {"env_file": ".env"}


settings = Settings()
