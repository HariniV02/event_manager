from builtins import ValueError, any, bool, str
from pydantic import BaseModel, EmailStr, Field, validator, root_validator
from typing import Optional, List
from datetime import datetime
from enum import Enum
import uuid
import re

from app.utils.nickname_gen import generate_nickname

class UserRole(str, Enum):
    ANONYMOUS = "ANONYMOUS"
    AUTHENTICATED = "AUTHENTICATED"
    MANAGER = "MANAGER"
    ADMIN = "ADMIN"

def validate_url(url: Optional[str]) -> Optional[str]:
    if url is None:
        return url
    url_regex = r'^https?:\/\/[^\s/$.?#].[^\s]*$'
    if not re.match(url_regex, url):
        raise ValueError('Invalid URL format')
    return url

class UserBase(BaseModel):
    email: EmailStr = Field(..., example="jason.doe@example.com")  # Email stays as is
    nickname: Optional[str] = Field(None, min_length=3, pattern=r'^[\w-]+$', example=generate_nickname())
    first_name: Optional[str] = Field(None, example="Jason")  # Changed to 'Jason'
    last_name: Optional[str] = Field(None, example="Doe")
    bio: Optional[str] = Field(None, example="Experienced software developer specializing in web applications.")
    profile_picture_url: Optional[str] = Field(None, example="https://example.com/profiles/jason.jpg")  # Updated example
    linkedin_profile_url: Optional[str] = Field(None, example="https://linkedin.com/in/jasondoe")  # Updated example
    github_profile_url: Optional[str] = Field(None, example="https://github.com/jasondoe")  # Updated example

    _validate_urls = validator('profile_picture_url', 'linkedin_profile_url', 'github_profile_url', pre=True, allow_reuse=True)(validate_url)
 
    class Config:
        from_attributes = True

class UserCreate(UserBase):
    email: EmailStr = Field(..., example="jason.doe@example.com")  # Email stays as is
    password: str = Field(..., example="Secure*1234")

class UserUpdate(UserBase):
    email: Optional[EmailStr] = Field(None, example="jason.doe@example.com")  # Email stays as is
    nickname: Optional[str] = Field(None, min_length=3, pattern=r'^[\w-]+$', example="jason_doe123")
    first_name: Optional[str] = Field(None, example="Jason")  # Changed to 'Jason'
    last_name: Optional[str] = Field(None, example="Doe")
    bio: Optional[str] = Field(None, example="Experienced software developer specializing in web applications.")
    profile_picture_url: Optional[str] = Field(None, example="https://example.com/profiles/jason.jpg")  # Updated example
    linkedin_profile_url: Optional[str] = Field(None, example="https://linkedin.com/in/jasondoe")  # Updated example
    github_profile_url: Optional[str] = Field(None, example="https://github.com/jasondoe")  # Updated example

    @root_validator(pre=True)
    def check_at_least_one_value(cls, values):
        if not any(values.values()):
            raise ValueError("At least one field must be provided for update")
        return values

class UserResponse(UserBase):
    id: uuid.UUID = Field(..., example=uuid.uuid4())
    role: UserRole = Field(default=UserRole.AUTHENTICATED, example="AUTHENTICATED")
    email: EmailStr = Field(..., example="jason.doe@example.com")  # Email stays as is
    nickname: Optional[str] = Field(None, min_length=3, pattern=r'^[\w-]+$', example=generate_nickname())    
    role: UserRole = Field(default=UserRole.AUTHENTICATED, example="AUTHENTICATED")
    is_professional: Optional[bool] = Field(default=False, example=True)

class LoginRequest(BaseModel):
    email: EmailStr = Field(..., example="jason.doe@example.com")  # Email stays as is
    password: str = Field(..., example="Secure*1234")

class ErrorResponse(BaseModel):
    error: str = Field(..., example="Not Found")
    details: Optional[str] = Field(None, example="The requested resource was not found.")

class UserListResponse(BaseModel):
    items: List[UserResponse] = Field(..., example=[{
        "id": uuid.uuid4(), "nickname": generate_nickname(), "email": "jason.doe@example.com",  # Email stays as is
        "first_name": "Jason", "bio": "Experienced developer", "role": "AUTHENTICATED",
        "last_name": "Doe", "bio": "Experienced developer", "role": "AUTHENTICATED",
        "profile_picture_url": "https://example.com/profiles/jason.jpg", 
        "linkedin_profile_url": "https://linkedin.com/in/jasondoe", 
        "github_profile_url": "https://github.com/jasondoe"
    }])
    total: int = Field(..., example=100)
    page: int = Field(..., example=1)
    size: int = Field(..., example=10)
