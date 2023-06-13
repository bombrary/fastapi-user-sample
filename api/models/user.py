from sqlalchemy import Column, Integer, String, ForeignKey

from api.db import Base


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True)
    name = Column(String(1024))
    email = Column(String(256), unique=True)
    password = Column(String(1024))
