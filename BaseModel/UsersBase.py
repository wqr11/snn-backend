from pydantic import BaseModel, EmailStr, Field


class UsersBase(BaseModel):
    email: EmailStr = Field(..., max_length=255)
    password: str
    description: str
    avatar_url: str
    is_group: bool