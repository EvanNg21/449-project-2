from flask import Flask, request, jsonify, session
from flask_session import Session
from werkzeug.security import generate_password_hash, check_password_hash
from models import db, User, InventoryItem
import re
import datetime
from datetime import timedelta
import time
import jwt
from functools import wraps

# ------------------------------------------------------------
# Configuration
# ------------------------------------------------------------

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+mysqlconnector://root:evan3610@localhost/freshmart' # connect to SQLite database, users,db
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False # disable tracking of modifications, saves system resources
app.config['SECRET_KEY'] = 'supersecretkey' # Flask session encryption key
app.config['SESSION_TYPE'] = 'filesystem' # file system to store session data, doesnt use cookies alone and makes sessions more secure.
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)  # session expiration time (30min)
app.config['JWT_SECRET_KEY'] = 'your_jwt_secret_key' # key for signing and verifying JWT tokens.

Session(app) # activates Flask-Session, session data will now be stored on the server filesystem
db.init_app(app) # intializes SQLAlchemy, connects User and InventoryItem models

with app.app_context(): # creates all the tables in models.py if they don’t already exist
    db.create_all()

# ------------------------------------------------------------
# User login and Admin login 
#        admin login
#       "username": "Admin123",
#       "password": "Admin123123!"
#   
#        regular user
#        "username": "User123",
#        "password": "User123123!"
#
# ------------------------------------------------------------

# User Registration
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json(silent=True)

     # Checks if JSON body is empty
    if not data:
        return jsonify({"error": "Request body is empty. Please provide user details."}), 400

    # Checks for missing fields
    if not all(field in data for field in ['username', 'email', 'password']):
        return jsonify({"error": "Missing required fields"}), 400
    
    #checks if all fields are strings
    if not all(isinstance(field, str) for field in ['username', 'email', 'password']):
        return jsonify({"error": "All fields must be strings"}), 400

    # Validates email format
    email_regex = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
    if not re.match(email_regex, data['email']):
        return jsonify({"error": "Invalid email format"}), 400

    # Validates password strength
    if len(data['password']) < 8:
        return jsonify({"error": "Password must be at least 8 characters long"}), 400
    if not re.search(r'\d', data['password']):
        return jsonify({"error": "Password must contain at least one digit."}), 400
    if not re.search(r'[A-Z]', data['password']):
        return jsonify({"error": "Password must contain at least one uppercase letter"}), 400
    if not re.search(r'[a-z]', data['password']):
        return jsonify({"error": "Password must contain at least one lowercase letter."}), 400
    if not re.search(r'[\W_]', data['password']):
        return jsonify({"error": "Password must contain at least one special character."}), 400

    # Checks if username or email is already taken
    existing_user = User.query.filter(
        (User.username == data['username']) | (User.email == data['email'])
    ).first()
    if existing_user:
        return jsonify({"error": "Username or Email already registered"}), 409

    # Hashes the password
    hashed_password = generate_password_hash(data['password'])

    # Get role from request data, default is 'user'
    role = data.get('role', 'user')

     # Creates new user
    new_user = User(
        username=data['username'],
        email=data['email'],
        password_hash=hashed_password,
        role=role
    )
    db.session.add(new_user)
    db.session.commit()

    return jsonify({"message": "User registered successfully!"}), 201


# User Login
@app.route('/login', methods=['POST'])
def login():
    data = request.json
    username = data['username']
    password = data['password']
    user = User.query.filter_by(username=data['username']).first()

    if not all(isinstance(field, str) for field in [username, password]):
        return jsonify({"error": "All fields must be strings"}), 400

    if user and check_password_hash(user.password_hash, data['password']):
        token = jwt.encode(
        {
            'username': username,
            'role': user.role,
            'id': user.id, 
            'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30)
        },
        app.config['JWT_SECRET_KEY'],
        algorithm="HS256"
    )
        session['user_id'] = user.id
        session['username'] = user.username
        session['jwt_token'] = token
        session['last_activity'] = time.time()  # Store the last activity timestamp
        response = jsonify({"message": "Login successful!"})
        response.set_cookie('logged_in', 'true', httponly=True, max_age=1800)
        return response
    
    return jsonify({"error": "Invalid credentials"}), 401


# Logout
@app.route('/logout', methods=['POST'])
def logout():
    session.pop('user_id', None)
    session.pop('username', None)
    session.pop('last_activity', None)  # Remove last activity timestamp
    session.clear()
    response = jsonify({"message": "User logged out successfully!"})
    response.set_cookie('logged_in', '', expires=0)
    response.set_cookie('admin_logged_in', '', expires=0)  # Clear cookie
    return response

#Admin Login (JWT-based)
@app.route('/admin/login', methods=['POST'])
def admin_login():
    data = request.json
    username = data.get("username")
    password = data.get("password")
    user = User.query.filter_by(username=username).first()
    if not user or not check_password_hash(user.password_hash, password):
        return jsonify({"message": "Bad credentials"}), 401
    if user.role != "admin":
        return jsonify({"message": "Not authorized. Admins only."}), 403
    # Create JWT
    token = jwt.encode(
        {
            'username': username,
            'role': user.role,
            'id': user.id, 
            'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30)
        },
        app.config['JWT_SECRET_KEY'],
        algorithm="HS256"
    )
    # Store session data for admin
    session['user_id'] = user.id
    session['username'] = user.username
    session['role'] = user.role
    session['jwt_token'] = token
    session['last_activity'] = time.time()

    response = jsonify({"access_token": token, "message": "Admin login successful!"})
    # Set secure cookie for demonstration
    response.set_cookie('admin_logged_in', 'true', httponly=True, max_age=1800)  # 30 minutes

    return response, 200

""" 
#Admin Logout
@app.route('/admin/logout', methods=['POST'])
def admin_logout():
    session.clear()  # Clears all session keys

    response = jsonify({"message": "Admin logged out successfully!"})
    response.set_cookie('admin_logged_in', '', expires=0)  # Clear cookie

    return response, 200
"""


# ------------------------------------------------------------
# Admin-Specific Inventory Management (JWT-protected)
# ------------------------------------------------------------

def jwt_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        
        token =  session.get('jwt_token')
        
        if not token:
            return jsonify({'message': 'Token is missing!'}), 401

        try:
            data = jwt.decode(token, app.config['JWT_SECRET_KEY'], algorithms=["HS256"])
            current_user = data  # Now contains both username and role
        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Token has expired!'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'message': 'Token is invalid!'}), 401
        
        return f(current_user, *args, **kwargs)
    
    return decorated

@app.route('/users', methods=['GET'])
def get_users():
   
    users = User.query.all()
    user_list = []
    for user in users:
        user_list.append({
            "id": user.id,
            "username": user.username,
            "email": user.email,
            "role": user.role
        })
    
    return jsonify(user_list), 200
@app.route('/inventory', methods=['GET'])
@jwt_required
def get_inventory(current_user):  # Current user details from JWT payload
    user_items = InventoryItem.query.filter_by(user_id=current_user['id']).all()
    if current_user['role'] == 'admin':
        user_items = InventoryItem.query.all()
    items = []
    for item in user_items:
        items.append({
            "id": item.id,
            "name": item.name,
            "description": item.description,
            "quantity": item.quantity,
            "price": item.price,
            "user_id": item.user_id
        })
    return jsonify(items), 200

# Create a new inventory item associated with the admin
@app.route('/inventory/create', methods=['POST'])
@jwt_required
def create_inventory_item(current_user):
    
    data = request.json
    name = data.get('name')
    if name is not None and not isinstance(name, str):
        return jsonify({"message": "Name must be a string"}), 400
    description = data.get('description')
    if description is not None and not isinstance(description, str):
        return jsonify({"message": "Description must be a string"}), 400
    quantity = data.get('quantity')
    if quantity is not None and not isinstance(quantity, int):
        return jsonify({"message": "Quantity must be an integer"}), 400
    price = data.get('price')
    if price is not None and not isinstance(price, float):
        return jsonify({"message": "Price must be a float"}), 400
    
    new_item = InventoryItem(
        name = name,
        description = description,
        quantity = quantity,
        price = price,
        user_id=current_user['id']  # Link the new item to the admin
    )
    db.session.add(new_item)
    db.session.commit()
    
    return jsonify({"message": "Inventory item created", "item_id": new_item.id}), 201

# Update an existing inventory item
@app.route('/admin/inventory/<int:item_id>', methods=['PUT'])
@jwt_required
def update_inventory_item(current_user, item_id):
    if current_user['role'] != 'admin':
        return jsonify({"message": "Admins only."}), 403

    # Ensure the item exists and belongs to the current admin.
    item = InventoryItem.query.filter_by(id=item_id).first()
    if not item:
        return jsonify({"message": "Item not found or not authorized"}), 404

    data = request.json
    name = data.get('name')
    if name is not None and not isinstance(name, str):
        return jsonify({"message": "Name must be a string"}), 400
    description = data.get('description')
    if description is not None and not isinstance(description, str):
        return jsonify({"message": "Description must be a string"}), 400
    quantity = data.get('quantity')
    if quantity is not None and not isinstance(quantity, int):
        return jsonify({"message": "Quantity must be an integer"}), 400
    price = data.get('price')
    if price is not None and not isinstance(price, float):
        return jsonify({"message": "Price must be a float"}), 400
    
    item.name = data.get('name', item.name)
    item.description = data.get('description', item.description)
    item.quantity = data.get('quantity', item.quantity)
    item.price = data.get('price', item.price)
    db.session.commit()
    
    return jsonify({"message": "Inventory item updated"}), 200

# Delete an inventory item
@app.route('/admin/inventory/<int:item_id>', methods=['DELETE'])
@jwt_required
def delete_inventory_item(current_user, item_id):
    if current_user['role'] != 'admin':
        return jsonify({"message": "Admins only."}), 403

    # Find the inventory item by ID
    item = InventoryItem.query.filter_by(id=item_id).first()
    if not item:
        return jsonify({"message": "Item not found"}), 404

    # Delete the item
    db.session.delete(item)
    db.session.commit()
    
    return jsonify({"message": "Inventory item deleted"}), 200
# ------------------------------------------------------------
# Session and Cookie Security
# ------------------------------------------------------------

@app.route('/session', methods=['GET'])
def get_session():
    # Check session expiration (if more than 30 minutes have passed since last activity)
    if 'last_activity' in session:
        if time.time() - session['last_activity'] > 30 * 60:  # If 30 minutes have passed, session will be expired
            session.pop('user_id', None)
            session.pop('username', None)
            session.pop('last_activity', None)
            return jsonify({"message": "Session expired. Please log in again."}), 401
        session['last_activity'] = time.time()  # Update the last activity timestamp
        return jsonify({
            "message": "User is logged in",
            "user_id": session['user_id'],
            "username": session['username']
        })
    return jsonify({"message": "User is not logged in"}), 401

# Protected Route (requires login)
@app.route('/logged_in', methods=['GET'])
def show_logged_in_page():
    # Check if session is expired or user is not logged in
    if 'user_id' not in session or (time.time() - session.get('last_activity', 0)) > 30 * 60:
        return jsonify({"message": "Please log in first"}), 401
    session['last_activity'] = time.time()  # Update the last activity timestamp
    return jsonify({"message": "Welcome! You are logged in."})

# ------------------------------------------------------------
# Run the Flask App
# ------------------------------------------------------------

if __name__ == '__main__':
    app.run(debug=True)