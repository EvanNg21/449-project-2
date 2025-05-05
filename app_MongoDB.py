from fastapi import FastAPI, Request, Response, Depends, HTTPException, status, Cookie
from fastapi.security import HTTPBearer
from fastapi.responses import JSONResponse
from pydantic import BaseModel, EmailStr
from bson import ObjectId  # needed to convert MongoDB _id to string, used in get_all_users()
from werkzeug.security import generate_password_hash, check_password_hash
from models_MongoDB import get_mongo_collections
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
SESSION_EXPIRATION_MINUTES = 30 # user will be logged out after 30 minutes of their login as their JWT will have expired

# get the collections from FreshMart MongoDB database
users_collection, inventory_collection = get_mongo_collections()



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

class InventoryCreate(BaseModel):
    name: str
    description: str
    quantity: int
    price: float

class InventoryUpdate(BaseModel):
    name: str | None = None
    description: str | None = None
    quantity: int | None = None
    price: float | None = None



# ------------------------------------------------------------
# User login and Admin login
# ------------------------------------------------------------

# User Registration using MongoDB
@app.post("/register")
def register_user(payload: RegisterRequest):
    data = payload.dict()

    # Check if user/email already exists
    if users_collection.find_one({"$or": [{"username": data["username"]}, {"email": data["email"]}]}):
        raise HTTPException(status_code=409, detail="Username or Email already registered")

    # Validate password strength 
    # Must be at least 8 chars long, contain one digit, contain one uppercase, contain one lowercase, and one special char
    if len(data['password']) < 8 or \
       not re.search(r'\d', data['password']) or \
       not re.search(r'[A-Z]', data['password']) or \
       not re.search(r'[a-z]', data['password']) or \
       not re.search(r'[\W_]', data['password']):
        raise HTTPException(status_code=400, detail="Password does not meet strength requirements")

    # Hashes the password
    hashed_password = generate_password_hash(data['password'])

    # new user info
    user_doc = {
        "username": data['username'],
        "email": data['email'],
        "password_hash": hashed_password,
        "role": data.get('role', 'user')
    }

    # insert the user into the collection
    users_collection.insert_one(user_doc)

    return {"message": "User registered successfully!"}

# User Login using MongoDB
@app.post("/login")
def user_login(payload: LoginRequest, response: Response):
    user = users_collection.find_one({"username": payload.username})

    # check if password is correct
    if not user or not check_password_hash(user["password_hash"], payload.password):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    # If it's an admin, return JWT explicitly
    # this data acts is thesession state. 
    # Instead of storing session info in a server-side memory or database, we store it securely inside the signed token itself
    token_data = {
        "username": user["username"],
        "id": str(user["_id"]),
        "role": user["role"],
        "exp": datetime.datetime.utcnow() + datetime.timedelta(minutes=SESSION_EXPIRATION_MINUTES)
    }

    # Secure user sessions with encryption (FAST api secret key) using JWT_SECRET_KEY
    token = jwt.encode(token_data, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)

    # creates the session by storing a signed JWT in a secure cookie (httponly=True prevents JavaScript access)
    response.set_cookie(key="session_token", 
                        value=token, 
                        httponly=True, 
                        max_age=SESSION_EXPIRATION_MINUTES * 60)
    
    if user["role"] == "admin":
        return {"access_token": token, "message": "Admin login successful!"}
    else:
        return {"message": "User login successful!"}

# Logout, same for User and Admin
@app.post("/logout")
def logout(response: Response):
    # removes the session from the browser by clearing the cookie
    response.delete_cookie(key="session_token")

    return {"message": "User logged out successfully!"}

# gets all the users in the database
@app.get("/users")
def get_all_users():
    users = users_collection.find()  # get all user documents
    user_list = []

    for user in users:
        user_info = {
            "id": str(user["_id"]),  # convert ObjectId to string
            "username": user["username"],
            "email": user["email"],
            "role": user["role"]
        }
        user_list.append(user_info)

    return {"users": user_list}



# ------------------------------------------------------------
# Admin-Specific Inventory Management (JWT-protected)
# ------------------------------------------------------------

# reads the JWT from the cookie and ensures the user is an admin
def get_current_admin(request: Request):
    token = request.cookies.get("session_token")
    if not token:
        raise HTTPException(status_code=401, detail="Not authenticated")

    try:
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token has expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")

    if payload.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admins only")

    return payload  # includes id, username, role


# ------------------------------------------------------------
# CRUD Operations for Inventory
# ------------------------------------------------------------

"""  Only admins can use these endpoints.  """

# create an item
@app.post("/inventory")
def create_inventory(item: InventoryCreate, admin=Depends(get_current_admin)):
    new_item = {
        "name": item.name,
        "description": item.description,
        "quantity": item.quantity,
        "price": item.price,
        "user_id": admin["id"]
    }
    result = inventory_collection.insert_one(new_item)
    return {"message": "Item created", "item_id": str(result.inserted_id)}

# gets all the items in the inventory
@app.get("/inventory")
def get_inventory(admin=Depends(get_current_admin)):
    items = inventory_collection.find({"user_id": admin["id"]})
    inventory_list = []
    for item in items:
        inventory_list.append({
            "id": str(item["_id"]),
            "name": item["name"],
            "description": item["description"],
            "quantity": item["quantity"],
            "price": item["price"]
        })
    return {"items": inventory_list}

# gets a single item in the inventory 
@app.get("/inventory/{item_id}")
def get_inventory_item(item_id: str, admin=Depends(get_current_admin)):
    item = inventory_collection.find_one({"_id": ObjectId(item_id), "user_id": admin["id"]})
    if not item:
        raise HTTPException(status_code=404, detail="Item not found")
    
    return {
        "id": str(item["_id"]),
        "name": item["name"],
        "description": item["description"],
        "quantity": item["quantity"],
        "price": item["price"]
    }

# update an item
@app.put("/inventory/{item_id}")
def update_inventory_item(item_id: str, updates: InventoryUpdate, admin=Depends(get_current_admin)):
    update_data = {k: v for k, v in updates.dict().items() if v is not None}
    result = inventory_collection.update_one(
        {"_id": ObjectId(item_id), "user_id": admin["id"]},
        {"$set": update_data}
    )
    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="Item not found or not authorized")
    
    return {"message": "Item updated"}

# delete an item
@app.delete("/inventory/{item_id}")
def delete_inventory_item(item_id: str, admin=Depends(get_current_admin)):
    result = inventory_collection.delete_one({"_id": ObjectId(item_id), "user_id": admin["id"]})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Item not found or not authorized")
    
    return {"message": "Item deleted"}
