from sqlalchemy import create_engine, Column, String, Integer, ForeignKey, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, sessionmaker
from datetime import datetime

Base = declarative_base()

class User(Base):
    __tablename__ = 'users'
    id = Column(Integer, primary_key=True)
    username = Column(String, unique=True)
    email = Column(String, unique=True)
    password = Column(String)
    created_at = Column(DateTime, default=datetime.utcnow)
    servers = relationship("MinecraftServer", back_populates="owner", cascade="all, delete-orphan")


class MinecraftServer(Base):
    __tablename__ = 'minecraft_servers'
    id = Column(Integer, primary_key=True)
    server_id = Column(String, unique=True)
    owner_id = Column(Integer, ForeignKey('users.id'))
    owner = relationship("User", back_populates="servers")

# Replace 'sqlite:///minecraft_database.db' with your desired database URI
engine = create_engine('sqlite:///minecraft_database.db', echo=True)
Base.metadata.create_all(engine)

# Create the database session
Session = sessionmaker(bind=engine)
session = Session()

print("Databases created successfully.")
