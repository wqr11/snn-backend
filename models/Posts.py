from sqlalchemy import Column, String, ForeignKey, DateTime, Integer
from sqlalchemy.orm import relationship
from datetime import datetime
from models.db_session import SqlAlchemyBase


class Posts(SqlAlchemyBase):
    __tablename__ = 'posts'

    id = Column(String, primary_key=True)
    title = Column(String, nullable=False)
    content = Column(String, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    likes_count = Column(Integer, default=0)

    owner_id = Column(String, ForeignKey("users.id"), nullable=False)
    owner = relationship("Users", back_populates="posts")

    attachments = relationship("Attachment", back_populates="post", cascade="all, delete")
    likes = relationship("PostLike", back_populates="post", cascade="all, delete")
