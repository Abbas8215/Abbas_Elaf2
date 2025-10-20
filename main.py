"""
FastAPI backend with:
- User Authentication (JWT)
- Profile Management (name, bio, image upload)
- Favorites System (add/remove/get)
- Full support for serving images hosted on Render
"""

from fastapi import FastAPI, Depends, HTTPException, Body, File, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel, EmailStr
from sqlalchemy.orm import Session
from passlib.context import CryptContext
from jose import jwt, JWTError
from datetime import datetime, timedelta
import shutil
import os

# Local modules
import models
from database import SessionLocal, engine

# ----------------------------------------------------------
# Configuration
# ----------------------------------------------------------
SECRET_KEY = "Abbas_elaf"       # Secret for encoding JWT tokens
ALGORITHM = "HS256"             # JWT signing algorithm
ACCESS_TOKEN_EXPIRE_MINUTES = 60
BASE_URL = "https://abbas-elaf2-3.onrender.com"  # public Render URL

pwd_context = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")

# Create all database tables if they don't exist
models.Base.metadata.create_all(bind=engine)

# ----------------------------------------------------------
# Application & Middleware
# ----------------------------------------------------------
app = FastAPI(title="NY Times Backend - Render Deployment")

# Enable CORS so the Flutter app can access this API
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],   # Use specific origins in production for security
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Serve static files (uploaded images under /media)
os.makedirs("media", exist_ok=True)
app.mount("/media", StaticFiles(directory="media"), name="media")

# ----------------------------------------------------------
# Schemas (Pydantic Models)
# ----------------------------------------------------------
class UserCreate(BaseModel):
    email: EmailStr
    password: str

class Token(BaseModel):
    access_token: str
    token_type: str

class UserProfile(BaseModel):
    name: str | None = None
    bio: str | None = None
    profile_image: str | None = None

# ----------------------------------------------------------
# Database Dependency
# ----------------------------------------------------------
def get_db():
    """
    Provides a SQLAlchemy session for dependency injection.
    Automatically closes the session after each request.
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# ----------------------------------------------------------
# Helper / Utility Functions
# ----------------------------------------------------------
def verify_password(plain_password, hashed_password):
    """Compare plain password with its hashed version."""
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    """Generate a new secure password hash using PBKDF2."""
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: timedelta = None):
    """
    Create a JWT access token that stores user info (`sub`).
    The token expires after a given time window.
    """
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

# ----------------------------------------------------------
# User Authentication Routes (Register/Login)
# ----------------------------------------------------------
@app.post("/register", status_code=201)
def register(user: UserCreate, db: Session = Depends(get_db)):
    """
    Create a new user if the email is not already taken.
    """
    existing = db.query(models.User).filter(models.User.email == user.email).first()
    if existing:
        raise HTTPException(status_code=400, detail="User already exists")

    hashed = get_password_hash(user.password)
    db_user = models.User(email=user.email, hashed_password=hashed)
    db.add(db_user)
    db.commit()
    db.refresh(db_user)

    return {"message": "User registered successfully", "email": db_user.email}


@app.post("/login", response_model=Token)
def login(form_data: UserCreate, db: Session = Depends(get_db)):
    """
    Authenticate the user by email and password.
    Returns a JWT token if credentials are valid.
    """
    user = db.query(models.User).filter(models.User.email == form_data.email).first()
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Incorrect email or password")

    token = create_access_token({"sub": user.email})
    return {"access_token": token, "token_type": "bearer"}

# OAuth2 configuration for secured routes
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

# ----------------------------------------------------------
# User Utility/functions for authentication
# ----------------------------------------------------------
def get_user_by_email(db: Session, email: str):
    """Return a single user object by email."""
    return db.query(models.User).filter(models.User.email == email).first()

def get_current_user_oauth(
    token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)
):
    """
    Extract user info (email) from JWT token.
    Return the user object if valid, or raise credentials error.
    """
    credentials_exception = HTTPException(
        status_code=401,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception

    user = get_user_by_email(db, email)
    if user is None:
        raise credentials_exception
    return user

# ----------------------------------------------------------
# Users Endpoints (Example Protected Routes)
# ----------------------------------------------------------
@app.get("/users")
def read_users(current_user: models.User = Depends(get_current_user_oauth),
               db: Session = Depends(get_db)):
    """
    Return a list of all registered users (Protected)
    Requires a valid Bearer token.
    """
    users = db.query(models.User).all()
    return {"count": len(users), "users": [u.email for u in users]}

@app.get("/users_unprotected")
def read_users_unprotected(db: Session = Depends(get_db)):
    """Publicly accessible list of all users (for testing)."""
    users = db.query(models.User).all()
    return {"count": len(users), "users": [u.email for u in users]}

# ----------------------------------------------------------
# Favorites Management (Add / Remove / Get)
# ----------------------------------------------------------
@app.get("/favorites")
def get_favorites(current_user: models.User = Depends(get_current_user_oauth),
                  db: Session = Depends(get_db)):
    """Return all favorite articles belonging to the logged-in user."""
    favs = db.query(models.Favorite).filter(models.Favorite.user_id == current_user.id).all()
    return [
        {
            "id": f.id,
            "article_id": f.article_id,
            "title": f.title,
            "thumbnail": f.thumbnail,
            "url": f.url,
        } for f in favs
    ]

@app.post("/favorites")
def add_favorite(article: dict = Body(...),
                 current_user: models.User = Depends(get_current_user_oauth),
                 db: Session = Depends(get_db)):
    """
    Add a new article to user's favorites.
    Prevents duplicates based on article_id.
    """
    exists = db.query(models.Favorite).filter(
        models.Favorite.article_id == article["article_id"],
        models.Favorite.user_id == current_user.id,
    ).first()
    if exists:
        raise HTTPException(status_code=400, detail="Already in favorites")

    fav = models.Favorite(
        user_id=current_user.id,
        article_id=article["article_id"],
        title=article.get("title", ""),
        thumbnail=article.get("thumbnail", ""),
        url=article.get("url", ""),
    )

    db.add(fav)
    db.commit()
    db.refresh(fav)
    return {"message": "Added to favorites"}

@app.delete("/favorites/{article_id}")
def remove_favorite(article_id: str,
                    current_user: models.User = Depends(get_current_user_oauth),
                    db: Session = Depends(get_db)):
    """Remove a favorite article by its unique article_id."""
    fav = db.query(models.Favorite).filter(
        models.Favorite.article_id == article_id,
        models.Favorite.user_id == current_user.id,
    ).first()

    if not fav:
        raise HTTPException(status_code=404, detail="Not found in favorites")

    db.delete(fav)
    db.commit()
    return {"message": "Removed from favorites"}

# ----------------------------------------------------------
# Profile Management
# ----------------------------------------------------------
@app.get("/profile")
def get_profile(current_user: models.User = Depends(get_current_user_oauth)):
    """
    Return full profile data of the current logged-in user.
    """
    return {
        "email": current_user.email,
        "name": current_user.name,
        "bio": current_user.bio,
        "profile_image": current_user.profile_image,
    }

@app.put("/profile")
def update_profile(profile: UserProfile,
                   current_user: models.User = Depends(get_current_user_oauth),
                   db: Session = Depends(get_db)):
    """
    Update profile info (name, bio, profile image URL).
    Does not require re-authentication if already logged in.
    """
    if profile.name is not None:
        current_user.name = profile.name
    if profile.bio is not None:
        current_user.bio = profile.bio
    if profile.profile_image is not None:
        current_user.profile_image = profile.profile_image

    db.commit()
    db.refresh(current_user)
    return {"message": "Profile updated successfully"}

# ----------------------------------------------------------
# Image Upload
# ----------------------------------------------------------
@app.post("/upload_profile_image")
def upload_profile_image(file: UploadFile = File(...),
                         current_user: models.User = Depends(get_current_user_oauth),
                         db: Session = Depends(get_db)):
    """
    Upload a new profile image:
    - Saves it under /media folder on the Render server.
    - Updates the user's profile_image field with a public URL.
    """
    os.makedirs("media", exist_ok=True)
    file_path = f"media/{current_user.id}_{file.filename}"

    # Save the uploaded image file
    with open(file_path, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)

    # Build full https URL so Flutter can access the image
    image_url = f"{BASE_URL}/{file_path}"

    current_user.profile_image = image_url
    db.commit()

    return {"message": "Image uploaded successfully", "path": image_url}