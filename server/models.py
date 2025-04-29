from sqlalchemy import Column, Integer, String, Boolean, DateTime
from database import Base
from datetime import datetime
from pydantic import BaseModel, EmailStr


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    email = Column(String, unique=True, index=True)
    password = Column(String)
    is_verified = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)


class UserCreate(BaseModel):
    username: str
    email: EmailStr
    password: str


class ResetPasswordRequest(BaseModel):
    token: str
    new_password: str


class ForgotPasswordRequest(BaseModel):
    email: EmailStr
