# models.py
# This file defines the SQLAlchemy models (database tables).

from sqlalchemy import Column, Integer, String, ForeignKey
from sqlalchemy.orm import relationship
from database import Base

# User table
class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    name = Column(String, nullable=True)
    profile_image = Column(String, nullable=True)
    bio = Column(String, nullable=True)

    # Relationship with the Favorite table
    favorites = relationship("Favorite", back_populates="user", cascade="all, delete")

# Favorite table (for storing saved articles)
class Favorite(Base):
    __tablename__ = "favorites"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    article_id = Column(String, nullable=False)
    title = Column(String)
    thumbnail = Column(String)
    url = Column(String)

    user = relationship("User", back_populates="favorites")