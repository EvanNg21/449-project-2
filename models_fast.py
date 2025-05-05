

from sqlalchemy import Column, Integer, String, Float, ForeignKey
from sqlalchemy.orm import declarative_base, relationship
from pymongo import MongoClient

# SQLAlchemy Base for relational (MySQL) database
Base = declarative_base()

# ----------------------------
# MySQL Models
# ----------------------------

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(150), unique=True, nullable=False)
    password_hash = Column(String(150), nullable=False)
    email = Column(String(150), unique=True, nullable=False)
    role = Column(String(20), default="user", nullable=False) # either admin or role

    items = relationship("InventoryItem", back_populates="owner")


class InventoryItem(Base):
    __tablename__ = "inventory"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(150), nullable=False)
    description = Column(String(150), nullable=False)
    quantity = Column(Integer, nullable=False)
    price = Column(Float, nullable=False)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)

    owner = relationship("User", back_populates="items")



# ----------------------------
# MongoDB Setup
# ----------------------------

def get_mongo_client():
    #Returns a MongoDB client connected to the 'FreshMart' database.
    
    client = MongoClient("mongodb://localhost:27017")
    db = client["FreshMart"]
    return db
