from typing import List, Optional
from pydantic import BaseModel

class UserRead(BaseModel):
    id: str
    email: str
    is_group: bool
    name: Optional[str] = None
    age: Optional[int] = None
    subscriptions_count: Optional[int] = None
    company_name: Optional[str] = None
    subscriber_count: Optional[int] = None
    description: Optional[str] = None
    main_tag: Optional[str] = None
    additional_tags: List[str] = []
    avatar_url: Optional[str] = None

    class Config:
        orm_mode = True
