import os
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

# Prefer an explicit DATABASE_URL, but fall back to a local SQLite file so
# development and tests do not require a running PostgreSQL instance.
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./backend.db")

engine = create_engine(DATABASE_URL, echo=False, future=True)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()


def get_db():
    """Dependency for FastAPI routes."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
