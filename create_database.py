from sqlalchemy import create_engine, Column, String, Integer
from sqlalchemy.ext.declarative import declarative_base

Base = declarative_base()

class User(Base):
    __tablename__ = 'users'
    id = Column(Integer, primary_key=True)
    username = Column(String, unique=True)
    password = Column(String)

# Replace 'sqlite:///database.db' with your database URI
engine = create_engine('sqlite:///database.db', echo=True)
Base.metadata.create_all(engine)
