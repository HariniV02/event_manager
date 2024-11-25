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
    """Validates the URL format."""
    if url is None:
        return url
    url_regex = r'^https?:\/\/[^\s/$.?#].[^\s]*$'
    if not re.match(url_regex, url):
        raise ValueError("Invalid URL format")
    return url


class UserBase(BaseModel):
    email: EmailStr = Field(..., example="johndoe@example.com")
    username: Optional[str] = Field(
        None,
        min_length=3,
        max_length=30,
        pattern=r'^[a-zA-Z0-9_.-]+$',
        example="john_doe",
    )
    nickname: Optional[str] = Field(
        None, min_length=3, pattern=r'^[\w-]+$', example=generate_nickname()
    )
    first_name: Optional[str] = Field(None, example="John")
    last_name: Optional[str] = Field(None, example="Doe")
    bio: Optional[str] = Field(
        None,
        example="Experienced software developer specializing in web applications.",
    )
    profile_picture_url: Optional[str] = Field(
        None, example="https://example.com/profiles/john.jpg"
    )
    linkedin_profile_url: Optional[str] = Field(
        None, example="https://linkedin.com/in/johndoe"
    )
    github_profile_url: Optional[str] = Field(
        None, example="https://github.com/johndoe"
    )

    _validate_urls = validator(
        "profile_picture_url",
        "linkedin_profile_url",
        "github_profile_url",
        pre=True,
        allow_reuse=True,
    )(validate_url)

    class Config:
        from_attributes = True


class UserCreate(UserBase):
    email: EmailStr = Field(..., example="johndoe@example.com")
    password: str = Field(..., example="Secure*1234")


class UserUpdate(UserBase):
    email: Optional[EmailStr] = Field(None, example="johndoe@example.com")
    username: Optional[str] = Field(
        None,
        min_length=3,
        max_length=30,
        pattern=r'^[a-zA-Z0-9_.-]+$',
        example="john_doe",
    )
    nickname: Optional[str] = Field(
        None, min_length=3, pattern=r'^[\w-]+$', example="john_doe123"
    )
    first_name: Optional[str] = Field(None, example="John")
    last_name: Optional[str] = Field(None, example="Doe")
    bio: Optional[str] = Field(
        None,
        example="Experienced software developer specializing in web applications.",
    )
    profile_picture_url: Optional[str] = Field(
        None, example="https://example.com/profiles/john.jpg"
    )
    linkedin_profile_url: Optional[str] = Field(
        None, example="https://linkedin.com/in/johndoe"
    )
    github_profile_url: Optional[str] = Field(
        None, example="https://github.com/johndoe"
    )

    @root_validator(pre=True)
    def check_at_least_one_value(cls, values): # pylint: disable=no-self-argument
        """Ensure at least one field is provided for update."""
        if not any(value is not None for value in values.values()):
            raise ValueError("At least one field must be provided for update")
        return values


class UserResponse(UserBase):
    id: uuid.UUID = Field(..., example=uuid.uuid4())
    role: UserRole = Field(default=UserRole.AUTHENTICATED, example="AUTHENTICATED")
    email: EmailStr = Field(..., example="johndoe@example.com")
    username: Optional[str] = Field(
        None,
        min_length=3,
        max_length=30,
        pattern=r'^[a-zA-Z0-9_.-]+$',
        example="john_doe",
    )
    nickname: Optional[str] = Field(
        None, min_length=3, pattern=r'^[\w-]+$', example=generate_nickname()
    )
    is_professional: Optional[bool] = Field(default=False, example=True)


class LoginRequest(BaseModel):
    email: str = Field(..., example="johndoe@example.com")
    password: str = Field(..., example="Secure*1234")


class ErrorResponse(BaseModel):
    error: str = Field(..., example="Not Found")
    details: Optional[str] = Field(
        None, example="The requested resource was not found."
    )


class UserListResponse(BaseModel):
    items: List[UserResponse] = Field(
        ...,
        example=[
            {
                "id": uuid.uuid4(),
                "username": "john_doe",
                "nickname": generate_nickname(),
                "email": "johndoe@example.com",
                "first_name": "John",
                "bio": "Experienced developer",
                "role": "AUTHENTICATED",
                "last_name": "Doe",
                "profile_picture_url": "https://example.com/profiles/john.jpg",
                "linkedin_profile_url": "https://linkedin.com/in/johndoe",
                "github_profile_url": "https://github.com/johndoe",
            }
        ],
    )
    total: int = Field(..., example=100)
    page: int = Field(..., example=1)
    size: int = Field(..., example=10)
