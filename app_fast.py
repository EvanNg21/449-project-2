from fastapi import FastAPI, Request, Response, Depends, HTTPException, status, Cookie
from fastapi.responses import JSONResponse
from pydantic import BaseModel, EmailStr
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import re
import time
import datetime

# ------------------------------------------------------------
# Configuration
# ------------------------------------------------------------

app = FastAPI()

# JWT config
JWT_SECRET_KEY = "secret_key"
JWT_ALGORITHM = "HS256"
SESSION_EXPIRATION_MINUTES = 30


# ----------------------------
# Pydantic Models
# ----------------------------
class RegisterRequest(BaseModel):
    username: str
    email: EmailStr
    password: str
    role: str = "user"

class LoginRequest(BaseModel):
    username: str
    password: str


# ------------------------------------------------------------
# User login and Admin login
# ------------------------------------------------------------

# User Registration
@app.post("/register")
def register_user(payload: RegisterRequest):
    data = payload.dict()

    # Check if user/email already exists
    existing_user = User.query.filter(
        (User.username == data['username']) | (User.email == data['email'])
    ).first()
    if existing_user:
        raise HTTPException(status_code=409, detail="Username or Email already registered")

    # Validate password strength
    if len(data['password']) < 8 or \
       not re.search(r'\d', data['password']) or \
       not re.search(r'[A-Z]', data['password']) or \
       not re.search(r'[a-z]', data['password']) or \
       not re.search(r'[\W_]', data['password']):
        raise HTTPException(status_code=400, detail="Password does not meet strength requirements")

    # Hashes the password
    hashed_password = generate_password_hash(data['password'])

    new_user = User(
        username=data['username'],
        email=data['email'],
        password_hash=hashed_password,
        role=data.get('role', 'user') # Get role from request data, default is 'user'
    )
    db.session.add(new_user)
    db.session.commit()

    return {"message": "User registered successfully!"}

# User Login
@app.post("/login")
def user_login(payload: LoginRequest, response: Response):
    user = User.query.filter_by(username=payload.username).first()

    if not user or not check_password_hash(user.password_hash, payload.password):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    token_data = {
        "username": user.username,
        "id": user.id,
        "role": user.role,
        "exp": datetime.datetime.utcnow() + datetime.timedelta(minutes=SESSION_EXPIRATION_MINUTES)
    }
    token = jwt.encode(token_data, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)

    response.set_cookie(key="session_token", value=token, httponly=True, max_age=SESSION_EXPIRATION_MINUTES*60)
    return {"message": "Login successful!"}

#Admin Login (JWT-based)
@app.post("/admin/login")
def admin_login(payload: LoginRequest, response: Response):
    user = User.query.filter_by(username=payload.username).first()

    if not user or not check_password_hash(user.password_hash, payload.password):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    if user.role != "admin":
        raise HTTPException(status_code=403, detail="Not authorized. Admins only.")

    token_data = {
        "username": user.username,
        "id": user.id,
        "role": user.role,
        "exp": datetime.datetime.utcnow() + datetime.timedelta(minutes=SESSION_EXPIRATION_MINUTES)
    }
    token = jwt.encode(token_data, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)

    response.set_cookie(key="session_token", value=token, httponly=True, max_age=SESSION_EXPIRATION_MINUTES*60)
    return {"access_token": token, "message": "Admin login successful!"}

# Logout, same for User and Admin
@app.post("/logout")
def logout(response: Response):
    response.delete_cookie(key="session_token")
    return {"message": "User logged out successfully!"}

