from fastapi import FastAPI, HTTPException, Depends
from sqlalchemy.orm import Session
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
import re
from database import SessionLocal, engine
from email_utils import send_verification_email, send_reset_password_email
from models import User, Base, UserCreate, ResetPasswordRequest, ForgotPasswordRequest
from auth import (
    hash_password,
    verify_password,
    create_access_token,
    decode_access_token,
)

Base.metadata.create_all(bind=engine)

app = FastAPI()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def password_strength(password: str) -> bool:
    return all(
        [
            len(password) >= 8,
            re.search(r"[A-Z]", password),
            re.search(r"[a-z]", password),
            re.search(r"[0-9]", password),
            re.search(r"[\W_]", password),
        ]
    )


@app.post("/register")
def register(user: UserCreate, db: Session = Depends(get_db)):
    if db.query(User).filter(User.username == user.username).first():
        raise HTTPException(status_code=400, detail="Username already registered")
    if db.query(User).filter(User.email == user.email).first():
        raise HTTPException(status_code=400, detail="Email already registered")
    if not password_strength(user.password):
        raise HTTPException(status_code=400, detail="Password too weak")

    new_user = User(
        username=user.username,
        email=user.email,
        password=hash_password(user.password),
        is_verified=False,
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    token = create_access_token(data={"sub": str(new_user.id)})
    send_verification_email(user.email, token)

    return {"msg": "User created successfully. Please verify your email."}


@app.post("/login")
def login(
    form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)
):
    user = db.query(User).filter(User.username == form_data.username).first()
    if not user or not verify_password(form_data.password, user.password):
        raise HTTPException(status_code=400, detail="Invalid credentials")
    if not user.is_verified:
        raise HTTPException(status_code=400, detail="Invalid credentials")

    access_token = create_access_token(data={"sub": str(user.id)})
    return {"access_token": access_token, "token_type": "bearer"}


def get_current_user(
    token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)
):
    user_id = decode_access_token(token)
    if user_id is None:
        raise HTTPException(status_code=401, detail="Invalid token")
    user = db.query(User).filter(User.id == int(user_id)).first()
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    return user


@app.get("/profile")
def read_profile(current_user: User = Depends(get_current_user)):
    return {"username": current_user.username}


@app.get("/verify-email")
def verify_email(token: str, db: Session = Depends(get_db)):
    user_id = decode_access_token(token)
    if user_id is None:
        raise HTTPException(status_code=400, detail="Invalid token")
    user = db.query(User).filter(User.id == int(user_id)).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    user.is_verified = True
    db.commit()
    return {"msg": "Email verified successfully"}


@app.post("/forgot-password")
def forgot_password(req: ForgotPasswordRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == req.email).first()
    if not user:
        raise HTTPException(status_code=404, detail="Email not registered")
    token = create_access_token(data={"sub": str(user.id)})
    send_reset_password_email(user.email, token)
    return {"msg": "Password reset email sent"}


@app.post("/reset-password")
def reset_password(req: ResetPasswordRequest, db: Session = Depends(get_db)):
    user_id = decode_access_token(req.token)
    if user_id is None:
        raise HTTPException(status_code=400, detail="Invalid token")
    user = db.query(User).filter(User.id == int(user_id)).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if not password_strength(req.new_password):
        raise HTTPException(status_code=400, detail="Password too weak")
    user.password = hash_password(req.new_password)
    db.commit()
    return {"msg": "Password reset successful"}
