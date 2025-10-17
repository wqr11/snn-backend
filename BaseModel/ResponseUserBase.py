from pydantic import BaseModel, EmailStr, Field

class UserRead(BaseModel):
    id: str
    email: EmailStr

    class Config:
        orm_mode = True