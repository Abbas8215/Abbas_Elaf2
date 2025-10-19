from fastapi import FastAPI, Depends, HTTPException, status,Body
from pydantic import BaseModel, EmailStr
from sqlalchemy.orm import Session
from passlib.context import CryptContext
from jose import jwt, JWTError
from datetime import datetime, timedelta
from fastapi.security import OAuth2PasswordBearer

import models
from database import SessionLocal, engine

SECRET_KEY = "Abbas_elaf"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

pwd_context = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")

models.Base.metadata.create_all(bind=engine)

app = FastAPI()

# ---------- Schemas ----------
class UserCreate(BaseModel):
    email: EmailStr
    password: str

class Token(BaseModel):
    access_token: str
    token_type: str

# ---------- Database Dependency ----------
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# ---------- Utils ----------
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

# ---------- Endpoints ----------
@app.post("/register", status_code=201)
def register(user: UserCreate, db: Session = Depends(get_db)):
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
    user = db.query(models.User).filter(models.User.email == form_data.email).first()
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Incorrect email or password")
    token = create_access_token({"sub": user.email})
    return {"access_token": token, "token_type": "bearer"}

# ---------- OAuth2 Protection ----------
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

def get_user_by_email(db: Session, email: str):
    return db.query(models.User).filter(models.User.email == email).first()

def get_current_user_oauth(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
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

@app.get("/users", tags=["users"])
def read_users(current_user: models.User = Depends(get_current_user_oauth), db: Session = Depends(get_db)):
    users = db.query(models.User).all()
    return {"count": len(users), "users": [u.email for u in users]}

@app.get("/users_unprotected", tags=["debug"])
def read_users_unprotected(db: Session = Depends(get_db)):
    users = db.query(models.User).all()
    return {"count": len(users), "users": [u.email for u in users]}

@app.get("/favorites", tags=["favorites"])
def get_favorites(
    current_user: models.User = Depends(get_current_user_oauth),
    db: Session = Depends(get_db),
):
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


@app.post("/favorites", tags=["favorites"])
def add_favorite(
    article: dict = Body(...),
    current_user: models.User = Depends(get_current_user_oauth),
    db: Session = Depends(get_db),
):
    # Avoid duplicate favorites per user
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


@app.delete("/favorites/{article_id}", tags=["favorites"])
def remove_favorite(
    article_id: str,
    current_user: models.User = Depends(get_current_user_oauth),
    db: Session = Depends(get_db),
):
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
