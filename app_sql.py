from fastapi import FastAPI, HTTPException, Depends, Request, Response
from models_sql import User, InventoryItem, Base
from sqlalchemy.orm import Session
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
from datetime import datetime, timedelta, timezone
from pydantic import BaseModel, field_validator
import re
from starlette.middleware.sessions import SessionMiddleware


DATABASE_URL = 'mysql+mysqlconnector://root:evan3610@localhost/freshmart'


engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

app = FastAPI()
app.add_middleware(SessionMiddleware, secret_key='your_secret_key')

Base.metadata.create_all(bind=engine)

JWT_SECRET_KEY = 'jwt_secret_key'

class TokenRequest(BaseModel):
    token: str

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
    @field_validator('name')
    def name_must_be_string(cls, v):
        if isinstance(v, int) or v.isdigit():
            raise ValueError("Name cannot be a number")
        return v
    
    @field_validator('description')
    def description_must_be_string(cls, v):
        if isinstance(v, int) or v.isdigit():
            raise ValueError("Description cannot be a number")
        return v

    @field_validator('price')
    def price_must_be_positive(cls, v):
        if not isinstance(v, float):
            raise ValueError("price must be an float")
        if v <= 0:
            raise ValueError("Price must be positive")
        return v

    @field_validator('quantity')
    def quantity_must_be_positive_integer(cls, v):
        if not isinstance(v, int):
            raise ValueError("Quantity must be an integer")
        if v < 0:
            raise ValueError("Quantity cannot be negative")
        return v

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
    email_regex = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
    if not re.match(email_regex, user.email):
        raise HTTPException(status_code=400, detail="Invalid email format")

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
def login(user: UserLogin, request: Request, response: Response, db: Session = Depends(get_db)):
    db_user = db.query(User).filter(User.username == user.username).first()
    if not db_user or not check_password_hash(db_user.password_hash, user.password):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    token = jwt.encode(
        {
            "username": db_user.username,
            "role": db_user.role,
            "id": db_user.id,
            "exp": datetime.now(timezone.utc) + timedelta(minutes=30),        },
        JWT_SECRET_KEY,
        algorithm="HS256",
    )
    request.session['user_id'] = db_user.id
    request.session['token'] = token
    response.set_cookie(
        key="access_token",
        value=f"Bearer {token}",
        httponly=True,
        max_age=1800,  
        secure=False, 
        samesite="lax", 
    )
    return {"message":"Logged in successfully", "token": token}

@app.post("/logout")
def logout(request: Request, response: Response):
    request.session.clear()
    response.delete_cookie("access_token")
    return {"message": "Logged out successfully"}

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
def get_current_user(request: Request):
    user_id = request.session.get('user_id')
    token = request.session.get('token')
    if not user_id or not token:
        raise HTTPException(status_code=401, detail="Not authenticated")

    try:
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=["HS256"])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")

@app.post("/inventory/create")
def create_inventory_item(
    item: InventoryItemCreate,
    request: Request,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    new_item = InventoryItem(
        name=item.name,
        description=item.description,
        quantity=item.quantity,
        price=item.price,
        user_id=current_user['id']
    )
    db.add(new_item)
    db.commit()
    return {"message": "Inventory item created"}

@app.get("/inventory")
def get_inventory(
    request: Request,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    if current_user['role'] == 'admin':
        items = db.query(InventoryItem).all()
    else:
        items = db.query(InventoryItem).filter(
            InventoryItem.user_id == current_user['id']
        ).all()
    return items

@app.put("/admin/inventory/{item_id}")
def update_inventory_item(
    item_id: int,
    item: InventoryItemCreate,
    request: Request,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
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
def delete_inventory_item(
    item_id: int,
    request: Request,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    if current_user['role'] != 'admin':
        raise HTTPException(status_code=403, detail="Admins only")

    db_item = db.query(InventoryItem).filter(InventoryItem.id == item_id).first()
    if not db_item:
        raise HTTPException(status_code=404, detail="Item not found")

    db.delete(db_item)
    db.commit()
    return {"message": "Inventory item deleted"}