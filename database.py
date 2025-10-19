# database.py
# This file configures the connection to the local SQLite database.

from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

# Define the database URL (here, a simple local SQLite file)
DATABASE_URL = "sqlite:///./users.db"

# Create the database engine
engine = create_engine(
    DATABASE_URL, connect_args={"check_same_thread": False}
)

# Create a session factory for database interactions
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)

# Base class for the ORM models
Base = declarative_base()