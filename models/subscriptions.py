from sqlalchemy import Column, String, ForeignKey, DateTime
from sqlalchemy.orm import relationship
from datetime import datetime
from models.db_session import SqlAlchemyBase

class Subscription(SqlAlchemyBase):
    __tablename__ = "subscriptions"

    id = Column(String, primary_key=True)
    user_id = Column(String, ForeignKey("users.id"))
    group_id = Column(String, ForeignKey("users.id"))
    created_at = Column(DateTime, default=datetime.utcnow)

    user = relationship("Users", foreign_keys=[user_id])
    group = relationship("Users", foreign_keys=[group_id])