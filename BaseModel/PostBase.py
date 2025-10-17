from pydantic import BaseModel, EmailStr

class PostBase(BaseModel):
    title: str
    content: str
