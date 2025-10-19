# main.py
# A simple FastAPI app with user authentication, profile management,
# and favorites handling (with image upload from the local device).

from fastapi import FastAPI, Depends, HTTPException, status, Body, File, UploadFile
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel, EmailStr
from sqlalchemy.orm import Session
from passlib.context import CryptContext
from jose import jwt, JWTError
from datetime import datetime, timedelta
import shutil
import os

import models
from database import SessionLocal, engine

# ---------- Configuration ----------
SECRET_KEY = "Abbas_elaf"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

# Password hashing configuration
pwd_context = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")

# Create database tables
models.Base.metadata.create_all(bind=engine)

# Initialize FastAPI app
app = FastAPI()

# ---------- Schemas ----------
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

# ---------- Database Dependency ----------
def get_db():
    """
    Dependency that creates and closes a database session.
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# ---------- Utils ----------
def verify_password(plain_password, hashed_password):
    """
    Check if a plain password matches its hashed version.
    """
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    """
    Return a secure hash of the given password.
    """
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: timedelta = None):
    """
    Generate a JWT access token containing user information.
    """
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

# ---------- Endpoints ----------

@app.post("/register", status_code=201)
def register(user: UserCreate, db: Session = Depends(get_db)):
    """
    Register a new user if the email is not already taken.
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
    Authenticate the user and return a JWT access token.
    """
    user = db.query(models.User).filter(models.User.email == form_data.email).first()
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Incorrect email or password")
    token = create_access_token({"sub": user.email})
    return {"access_token": token, "token_type": "bearer"}

# OAuth2 setup
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

def get_user_by_email(db: Session, email: str):
    return db.query(models.User).filter(models.User.email == email).first()

def get_current_user_oauth(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    """
    Get the currently authenticated user based on the provided token.
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

# ---------- Example Protected and Unprotected Routes ----------

@app.get("/users")
def read_users(current_user: models.User = Depends(get_current_user_oauth), db: Session = Depends(get_db)):
    """
    Return a list of all user emails (protected route).
    """
    users = db.query(models.User).all()
    return {"count": len(users), "users": [u.email for u in users]}

@app.get("/users_unprotected")
def read_users_unprotected(db: Session = Depends(get_db)):
    """
    Return a list of all users (unprotected route for debugging).
    """
    users = db.query(models.User).all()
    return {"count": len(users), "users": [u.email for u in users]}

# ---------- Favorite Articles ----------

@app.get("/favorites")
def get_favorites(
    current_user: models.User = Depends(get_current_user_oauth),
    db: Session = Depends(get_db),
):
    """
    Get all favorite articles for the logged-in user.
    """
    favs = (
        db.query(models.Favorite)
        .filter(models.Favorite.user_id == current_user.id)
        .all()
    )
    return [
        {
            "id": f.id,
            "article_id": f.article_id,
            "title": f.title,
            "thumbnail": f.thumbnail,
            "url": f.url,
        }
        for f in favs
    ]


@app.post("/favorites")
def add_favorite(
    article: dict = Body(...),
    current_user: models.User = Depends(get_current_user_oauth),
    db: Session = Depends(get_db),
):
    """
    Add a new favorite article for the current user.
    Prevent duplicates.
    """
    exists = (
        db.query(models.Favorite)
        .filter(
            models.Favorite.article_id == article["article_id"],
            models.Favorite.user_id == current_user.id,
        )
        .first()
    )
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
def remove_favorite(
    article_id: str,
    current_user: models.User = Depends(get_current_user_oauth),
    db: Session = Depends(get_db),
):
    """
    Remove a favorite article by its ID.
    """
    fav = (
        db.query(models.Favorite)
        .filter(
            models.Favorite.article_id == article_id,
            models.Favorite.user_id == current_user.id,
        )
        .first()
    )
    if not fav:
        raise HTTPException(status_code=404, detail="Not found in favorites")

    db.delete(fav)
    db.commit()
    return {"message": "Removed from favorites"}

# ---------- Profile Management ----------

@app.get("/profile")
def get_profile(current_user: models.User = Depends(get_current_user_oauth)):
    """
    Return the current user's profile information.
    """
    return {
        "email": current_user.email,
        "name": current_user.name,
        "bio": current_user.bio,
        "profile_image": current_user.profile_image,
    }

@app.put("/profile")
def update_profile(
    profile: UserProfile,
    current_user: models.User = Depends(get_current_user_oauth),
    db: Session = Depends(get_db),
):
    """
    Update the current user's profile information.
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

# ---------- Image Upload ----------
@app.post("/upload_profile_image")
def upload_profile_image(
    file: UploadFile = File(...),
    current_user: models.User = Depends(get_current_user_oauth),
    db: Session = Depends(get_db),
):
    """
    Upload a profile image directly from the user's local device. 
    The file will be stored in a local 'media' folder.
    """
    os.makedirs("media", exist_ok=True)  # Ensure the folder exists
    file_path = f"media/{current_user.id}_{file.filename}"

    # Save the uploaded file locally
    with open(file_path, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)

    # Save file path to user's profile
    current_user.profile_image = file_path
    db.commit()
    return {"message": "Image uploaded successfully", "path": file_path}