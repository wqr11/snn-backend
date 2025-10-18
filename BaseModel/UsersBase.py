from pydantic import BaseModel, EmailStr, model_validator
from typing import Optional, List

class UsersBase(BaseModel):
    email: EmailStr
    phone: Optional[str] = None  # новое поле
    password: str
    is_group: bool
    description: Optional[str] = None

    # Для групп
    company_name: Optional[str] = None
    main_tag: Optional[str] = None
    additional_tags: Optional[List[str]] = None

    # Для пользователей
    name: Optional[str] = None
    age: Optional[int] = None

    @model_validator(mode="before")
    def check_required_fields(cls, values):
        is_group = values.get("is_group")
        if is_group:
            required = ["company_name", "main_tag", "additional_tags"]
        else:
            required = ["name", "age"]
        missing = [field for field in required if values.get(field) is None]
        if missing:
            raise ValueError(f"Missing required fields: {missing}")
        return values
