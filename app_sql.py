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


# -------------------
# Pydantic Models
# -------------------

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
            raise ValueError("price must be a float")
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


# -------------------
# Dependency
# -------------------

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# -------------------
# Auth Endpoints
# -------------------

@app.post("/register")
def register(user: UserCreate, db: Session = Depends(get_db)):
    email_regex = r'^[\w\.\-]+@[\w\-]+\.[\w\.\-]+$'
    if not re.match(email_regex, user.email):
        raise HTTPException(400, "Invalid email format")

    if (len(user.password) < 8
        or not re.search(r'\d', user.password)
        or not re.search(r'[A-Z]', user.password)
        or not re.search(r'[a-z]', user.password)
        or not re.search(r'[\W_]', user.password)):
        raise HTTPException(400, "Password must be strong")

    exists = db.query(User).filter(
        (User.username==user.username)|(User.email==user.email)
    ).first()
    if exists:
        raise HTTPException(409, "Username or Email already registered")

    hashed = generate_password_hash(user.password)
    db.add(User(
        username=user.username,
        email=user.email,
        password_hash=hashed,
        role=user.role
    ))
    db.commit()
    return {"message":"User registered successfully!"}


@app.post("/login")
def login(user: UserLogin, request: Request, response: Response, db: Session = Depends(get_db)):
    db_user = db.query(User).filter(User.username==user.username).first()
    if not db_user or not check_password_hash(db_user.password_hash, user.password):
        raise HTTPException(401, "Invalid credentials")

    token = jwt.encode({
        "username": db_user.username,
        "role":     db_user.role,
        "id":       db_user.id,
        "exp":      datetime.now(timezone.utc) + timedelta(minutes=30)
    }, JWT_SECRET_KEY, algorithm="HS256")

    # store only JSON‑serializable values
    request.session['user_id']     = db_user.id
    request.session['token']       = token
    request.session['login_time']  = datetime.now(timezone.utc).isoformat()

    response.set_cookie(
        "access_token",
        f"Bearer {token}",
        httponly=True,
        max_age=1800,
        secure=False,
        samesite="lax",
    )
    return {"message":"Logged in successfully","token":token}


@app.post("/logout")
def logout(request: Request, response: Response):
    request.session.clear()
    response.delete_cookie("access_token")
    return {"message":"Logged out successfully"}


# -------------------
# Protected Inventory
# -------------------

def get_current_user(request: Request):
    token = request.session.get("token")
    if not token:
        raise HTTPException(401, "Not authenticated")
    try:
        return jwt.decode(token, JWT_SECRET_KEY, algorithms=["HS256"])
    except jwt.ExpiredSignatureError:
        raise HTTPException(401, "Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(401, "Invalid token")


@app.post("/inventory/create")
def create_item(
    item: InventoryItemCreate,
    db: Session = Depends(get_db),
    user=Depends(get_current_user)
):
    db_item = InventoryItem(
        name=item.name,
        description=item.description,
        quantity=item.quantity,
        price=item.price,
        user_id=user["id"]
    )
    db.add(db_item)
    db.commit()
    return {"message":"Inventory item created"}


@app.get("/inventory")
def list_items(
    db: Session = Depends(get_db),
    user=Depends(get_current_user)
):
    if user["role"]=="admin":
        items = db.query(InventoryItem).all()
    else:
        items = db.query(InventoryItem).filter(InventoryItem.user_id==user["id"]).all()
    return items
