# ----------------------------
# MongoDB Setup
# ----------------------------

from pymongo import MongoClient

def get_mongo_collections():
    client = MongoClient("mongodb://localhost:27017")
    db = client["FreshMart"]  # database name
    users = db["users"] # user collection
    inventory = db["inventory"] # inventory collection

    # create indexes (only runs once, MongoDB skips if index already exists)
    users.create_index("username", unique=True)
    users.create_index("email", unique=True)
    inventory.create_index("user_id")

    return users, inventory


"""

Terminal code MongoDB:
mongosh
    show dbs
    use db_name
    show collections
    db.collection_name.find()      shows all the documents in a collection
    
    use FreshMart
    db.users.getIndexes()
    db.inventory.getIndexes()
exit

"""
