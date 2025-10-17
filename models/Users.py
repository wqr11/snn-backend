import sqlalchemy
from models.db_session import SqlAlchemyBase
from sqlalchemy.orm import relationship

class Users(SqlAlchemyBase):
    __tablename__ = 'users'

    id = sqlalchemy.Column(sqlalchemy.String, primary_key=True)
    email = sqlalchemy.Column(sqlalchemy.String, nullable=False, unique=True)
    password = sqlalchemy.Column(sqlalchemy.String, nullable=False)
    description = sqlalchemy.Column(sqlalchemy.String, nullable=True)
    avatar_url = sqlalchemy.Column(sqlalchemy.String, nullable=True)
    is_group = sqlalchemy.Column(sqlalchemy.Boolean, nullable=False)
    posts = relationship("Posts", back_populates="owner", cascade="all, delete")



