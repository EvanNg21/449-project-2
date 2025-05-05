from fastapi import FastAPI, HTTPException, Depends, Request
from models import User, InventoryItem, Base
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session
from sqlalchemy import create_engine, Column, Integer, String, Float, ForeignKey
from sqlalchemy.orm import sessionmaker, declarative_base, relationship
from models import User
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
from datetime import datetime, timedelta
from pydantic import BaseModel
import re

DATABASE_URL = 'mysql+mysqlconnector://root:evan3610@localhost/freshmart'

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

app = FastAPI()

Base.metadata.create_all(bind=engine)

JWT_SECRET_KEY = 'your_jwt_secret_key'
user_token = ""

# ------------------------------------------------------------
# Models
# ------------------------------------------------------------

class UserCreate(BaseModel):
    username: str
    email: str
    password: str
    role: str = "user"

class UserLogin(BaseModel):
    username: str
    password: str

class InventoryItemCreate(BaseModel):
    name: str
    description: str
    quantity: int
    price: float

# ------------------------------------------------------------
# Dependency
# ------------------------------------------------------------

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# ------------------------------------------------------------
# User Registration and Login
# ------------------------------------------------------------

@app.post("/register")
def register(user: UserCreate, db: Session = Depends(get_db)):
    # Validate email format
    email_regex = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
    if not re.match(email_regex, user.email):
        raise HTTPException(status_code=400, detail="Invalid email format")

    # Validate password strength
    if len(user.password) < 8 or not re.search(r'\d', user.password) or not re.search(r'[A-Z]', user.password) or not re.search(r'[a-z]', user.password) or not re.search(r'[\W_]', user.password):
        raise HTTPException(status_code=400, detail="Password must be strong")

    existing_user = db.query(User).filter((User.username == user.username) | (User.email == user.email)).first()
    if existing_user:
        raise HTTPException(status_code=409, detail="Username or Email already registered")

    hashed_password = generate_password_hash(user.password)
    new_user = User(username=user.username, email=user.email, password_hash=hashed_password, role=user.role)
    db.add(new_user)
    db.commit()

    return {"message": "User registered successfully!"}

@app.post("/login")
def login(user: UserLogin, db: Session = Depends(get_db)):
    db_user = db.query(User).filter(User.username == user.username).first()
    if not db_user or not check_password_hash(db_user.password_hash, user.password):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    global user_token
    user_token = jwt.encode({"username": db_user.username, "role": db_user.role, "id": db_user.id, "exp": datetime.utcnow() + timedelta(minutes=30)}, JWT_SECRET_KEY, algorithm="HS256")
    return {"access_token": user_token, "token_type": "bearer"}

@app.post("/logout")
def logout(token: str):
    try:
       
        jwt.decode(token, JWT_SECRET_KEY, algorithms=["HS256"])
        
        global user_token
        user_token = ""
        return {"message": "Logged out successfully. Please discard your token."}
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token has expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")

class UserResponse(BaseModel):
    id: int
    username: str
    email: str
    role: str

    class Config:
        orm_mode = True


@app.get("/users", response_model=list[UserResponse])
def get_users(db: Session = Depends(get_db)):
    users = db.query(User).all()
    return users
# ------------------------------------------------------------
# Inventory Management (JWT-protected)
# ------------------------------------------------------------

def jwt_required(token: str):
    try:
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=["HS256"])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token has expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")

@app.post("/inventory/create")
def create_inventory_item(item: InventoryItemCreate, token: str, db: Session = Depends(get_db)):
    current_user = jwt_required(token)
    
    new_item = InventoryItem(name=item.name, description=item.description, quantity=item.quantity, price=item.price, user_id=current_user['id'])
    db.add(new_item)
    db.commit()

    return {"message": "Inventory item created"}

@app.get("/inventory")
def get_inventory(token: str, db: Session = Depends(get_db)):
    current_user = jwt_required(token)
    if current_user['role'] == 'admin':
        items = db.query(InventoryItem).all()
    else:
        items = db.query(InventoryItem).filter(InventoryItem.user_id == current_user['id']).all()

    return items

@app.put("/admin/inventory/{item_id}")
def update_inventory_item(item_id: int, item: InventoryItemCreate, token: str, db: Session = Depends(get_db)):
    current_user = jwt_required(token)
    if current_user['role'] != 'admin':
        raise HTTPException(status_code=403, detail="Admins only")

    db_item = db.query(InventoryItem).filter(InventoryItem.id == item_id).first()
    if not db_item:
        raise HTTPException(status_code=404, detail="Item not found")

    db_item.name = item.name
    db_item.description = item.description
    db_item.quantity = item.quantity
    db_item.price = item.price
    db.commit()

    return {"message": "Inventory item updated"}

@app.delete("/admin/inventory/{item_id}")
def delete_inventory_item(item_id: int, token: str, db: Session = Depends(get_db)):
    current_user = jwt_required(token)
    if current_user['role'] != 'admin':
        raise HTTPException(status_code=403, detail="Admins only")

    db_item = db.query(InventoryItem).filter(InventoryItem.id == item_id).first()
    if not db_item:
        raise HTTPException(status_code=404, detail="Item not found")

    db.delete(db_item)
    db.commit()

    return {"message": "Inventory item deleted"}