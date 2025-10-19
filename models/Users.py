from sqlalchemy import Column, String, Integer, Boolean, CheckConstraint, ARRAY
from sqlalchemy.orm import relationship
from models.db_session import SqlAlchemyBase

class Users(SqlAlchemyBase):
    __tablename__ = "users"

    id = Column(String, primary_key=True)
    email = Column(String, nullable=False, unique=True)  # общий для всех
    phone = Column(String, nullable=True, unique=True)   # новый общий для всех
    password = Column(String, nullable=False)
    is_group = Column(Boolean, nullable=False, default=False)

    # Общие поля
    avatar_url = Column(String, nullable=True)
    description = Column(String, nullable=True)
    main_tag = Column(String, nullable=False)
    additional_tags = Column(ARRAY(String), default=[])
    posts_count = Column(Integer, default=0)

    # Только для групп
    company_name = Column(String, nullable=True)
    subscriber_count = Column(Integer, nullable=True, default=0)  # кол-во подписчиков

    # Только для обычных пользователей
    name = Column(String, nullable=True)
    age = Column(Integer, nullable=True)
    subscriptions_count = Column(Integer, nullable=True, default=0)  # кол-во подписок

    # Связи
    posts = relationship("Posts", back_populates="owner", cascade="all, delete")

    # Подписки
    subscriptions = relationship(
        "Subscription",
        foreign_keys="[Subscription.user_id]",
        back_populates="user",
        cascade="all, delete-orphan"
    )
    # Подписчики (только для группы)
    subscribers = relationship(
        "Subscription",
        foreign_keys="[Subscription.group_id]",
        back_populates="group",
        cascade="all, delete-orphan"
    )

    __table_args__ = (
        CheckConstraint(
            # Проверка валидности данных для пользователей и групп
            "(is_group = true AND company_name IS NOT NULL AND main_tag IS NOT NULL AND name IS NULL AND age IS NULL) "
            "OR "
            "(is_group = false AND name IS NOT NULL AND age IS NOT NULL AND main_tag IS NOT NULL AND company_name IS NULL)",
            name="check_user_group_data_validity"
        ),
    )