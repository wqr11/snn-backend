from pydantic import BaseModel, EmailStr, Field
from fastapi import File, UploadFile

class UsersUpdateBase(BaseModel):

    email: EmailStr = Field(..., max_length=255)
    previous_password: str
    password: str
    description: str
    avatar_url: UploadFile = File(None),