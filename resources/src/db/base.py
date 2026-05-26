from sqlmodel import SQLModel

# Import all models so Alembic autogenerate detects them
from src.models import *  # noqa: F401, F403

Base = SQLModel.metadata
