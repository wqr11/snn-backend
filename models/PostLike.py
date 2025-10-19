from sqlalchemy import Column, String, ForeignKey, DateTime
from sqlalchemy.orm import relationship
from datetime import datetime
from models.db_session import SqlAlchemyBase


class PostLike(SqlAlchemyBase):
    __tablename__ = "post_likes"

    id = Column(String, primary_key=True)
    post_id = Column(String, ForeignKey("posts.id"), nullable=False)
    user_id = Column(String, ForeignKey("users.id"), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

    post = relationship("Posts", back_populates="likes")
    user = relationship("Users")
