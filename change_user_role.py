from pymongo import MongoClient
import os
from dotenv import load_dotenv

# Load env
load_dotenv(".env")

client = MongoClient(os.getenv("MONGO_URI"))
db = client['payment_gateway_db']
users_collection = db['users']

# Update role only
users_collection.update_one(
    {"userId": "user_7fa16bba5311"},  # Filter by userId
    {"$set": {"role": "admin"}}     # Only changes the role
)

print("User role updated successfully, password intact.")


#==================================================================

