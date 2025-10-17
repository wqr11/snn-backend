from sqlalchemy import Column, String, ForeignKey
from sqlalchemy.orm import relationship
from models.db_session import SqlAlchemyBase

class Attachment(SqlAlchemyBase):
    __tablename__ = "attachments"

    id = Column(String, primary_key=True)
    file_url = Column(String, nullable=False)
    post_id = Column(String, ForeignKey("posts.id"))
    # 🔄 Связь с Posts
    post = relationship("Posts", back_populates="attachments")