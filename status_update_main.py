# ============================================================
# 🏦 MOCK PAYMENT GATEWAY API
# Description: FastAPI-based mock payment gateway using MongoDB.
# ============================================================

from fastapi import FastAPI, HTTPException, status, BackgroundTasks, Depends, Header
import time
from datetime import datetime, timezone, timedelta 
import httpx 
import uuid 
from pydantic import BaseModel, Field, validator
from typing import Optional
import asyncio

# ============================================================
# 1️⃣  MONGODB CONFIGURATION & INITIALIZATION
# ============================================================

import os 
from dotenv import load_dotenv
from pymongo import MongoClient
from pymongo.collection import Collection
from pymongo.errors import ConnectionFailure
from bson.objectid import ObjectId

# --- Load Environment Variables ---
load_dotenv(dotenv_path='.env')

# --- MongoDB Configuration ---
MONGO_URI = os.getenv("MONGO_URI") 
if not MONGO_URI:
    print("[DB ERROR] MONGO_URI not found. Check your .env file.")
    exit(1)

DB_NAME = "payment_gateway_db"
COLLECTION_NAME = "transactions"

# --- Database Initialization ---
try:
    client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=5000)
    client.admin.command('ping')
    mongo_db = client[DB_NAME]
    print(f"[DB] Connected to MongoDB Atlas → Database: '{DB_NAME}'.")
except ConnectionFailure as e:
    print(f"[DB ERROR] Could not connect to MongoDB: {e}")
except Exception as e:
    print(f"[DB ERROR] Unexpected error: {e}")

def get_mongo_collection() -> Collection:
    try:
        if 'mongo_db' not in globals():
             raise NameError("Database client not initialized.")
        return mongo_db[COLLECTION_NAME]
    except NameError as e:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Database not initialized: {e}"
        )

# ============================================================
# 2️⃣  AUTHENTICATION & USER VALIDATION
# ============================================================

# MOCK_API_KEYS = {...}  # Optional fallback if needed

def get_current_user_id(x_api_key: str = Header(..., alias="X-API-Key")) -> str:
    if 'mongo_db' in globals():
        users_collection = mongo_db["users"]
        user_doc = users_collection.find_one({"apiKey": x_api_key})
        if user_doc:
            return user_doc["userId"]

    user_id = MOCK_API_KEYS.get(x_api_key)
    if user_id:
        return user_id

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or missing X-API-Key. Access denied."
    )

# ============================================================
# 3️⃣  APPLICATION SETUP
# ============================================================

app = FastAPI()
app_start_time = time.monotonic()
STATUS_WEBHOOK_URL = "https://webhook-placeholder.com/your-webhook-url"

# ============================================================
# 2️⃣.5️⃣  USER REGISTRATION (Dynamic API Key Generation)
# ============================================================

USERS_COLLECTION_NAME = "users"

def get_users_collection() -> Collection:
    try:
        if 'mongo_db' not in globals():
            raise NameError("Database client not initialized.")
        return mongo_db[USERS_COLLECTION_NAME]
    except NameError as e:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Database not initialized: {e}"
        )

class UserRegistration(BaseModel):
    name: str = Field(..., min_length=2)
    email: str = Field(..., pattern=r'^[\w\.-]+@[\w\.-]+\.\w+$')

def generate_api_key() -> str:
    return f"PK_LIVE_{uuid.uuid4().hex[:16].upper()}"

@app.post("/api/v1/users/register", status_code=status.HTTP_201_CREATED)
async def register_user(
    user: UserRegistration,
    users_collection: Collection = Depends(get_users_collection)
):
    existing_user = users_collection.find_one({"email": user.email})
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User with this email already exists."
        )

    user_id = f"user_{uuid.uuid4().hex[:12]}"
    api_key = generate_api_key()
    created_at = datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')

    user_doc = {
        "userId": user_id,
        "name": user.name,
        "email": user.email,
        "apiKey": api_key,
        "createdAt": created_at
    }

    try:
        users_collection.insert_one(user_doc)
    except Exception as e:
        print(f"[DB ERROR] Failed to create user record: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Database error while creating user."
        )

    print(f"[REGISTER] New user created: {user_id} ({user.email})")
    return {
        "message": "User registered successfully.",
        "userId": user_id,
        "apiKey": api_key,
        "createdAt": created_at
    }

# ============================================================
# 4️⃣  DATA MODELS
# ============================================================

class PaymentCharge(BaseModel):
    customerName: str = Field(..., min_length=1)
    paymentAmount: float = Field(..., gt=0)
    currency: str = Field(..., max_length=3)
    details: Optional[str] = Field(None)
    webhookUrl: Optional[str] = Field(None)

    @validator('customerName')
    def name_must_not_be_blank(cls, value):
        if not value.strip():
            raise ValueError('Customer name cannot be empty or whitespace.')
        return value.strip()

# ============================================================
# 5️⃣  UTILITY FUNCTIONS
# ============================================================

async def dispatch_webhook(url: str, payload: dict):
    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(url, json=payload, timeout=5.0)
            print(f"[WEBHOOK] Sent to {url}. Status: {response.status_code}")
    except httpx.RequestError as exc:
        print(f"[WEBHOOK ERROR] Failed to send webhook: {exc}")

async def complete_payment_after_delay(transaction_id: str, collection: Collection, webhook_url: str):
    """Wait 5 seconds, mark payment as completed, and send webhook."""
    await asyncio.sleep(5)  # realistic processing delay

    # Update status in MongoDB
    updated = collection.find_one_and_update(
        {"id": transaction_id},
        {"$set": {"status": "completed"}},
        return_document=True
    )

    if updated and webhook_url:
        payload = {
            "event": "payment.completed",
            "id": updated["id"],
            "timestamp": datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'),
            "data": {
                "customerName": updated["customerName"],
                "amount": updated["amount"],
                "currency": updated["currency"],
                "status": updated["status"]
            }
        }
        await dispatch_webhook(webhook_url, payload)
        print(f"[BACKGROUND] Transaction {transaction_id} marked as completed and webhook sent.")

# ============================================================
# 6️⃣  API ENDPOINTS
# ============================================================

@app.post("/api/v1/payments/charge", status_code=status.HTTP_201_CREATED)
async def process_new_payment(
    charge: PaymentCharge, 
    background_tasks: BackgroundTasks, 
    collection: Collection = Depends(get_mongo_collection),
    owner_id: str = Depends(get_current_user_id)
):
    transaction_id = f"txn_{uuid.uuid4().hex[:12]}"
    created_at = datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')

    new_transaction = {
        "id": transaction_id,
        "ownerId": owner_id,
        "customerName": charge.customerName,
        "amount": charge.paymentAmount,
        "currency": charge.currency,
        "details": charge.details or 'No details provided',
        "status": 'pending',  # <-- start as pending
        "webhookUrl": charge.webhookUrl,
        "createdAt": created_at
    }

    # Persist to MongoDB
    try:
        collection.insert_one(new_transaction)
    except Exception as e:
        print(f"[DB ERROR] Failed to insert transaction {transaction_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Database error while saving transaction."
        )

    print(f"[CHARGE] New transaction created: {transaction_id} (Owner: {owner_id})")

    # Schedule background task to complete payment
    if new_transaction["webhookUrl"]:
        background_tasks.add_task(
            complete_payment_after_delay,
            transaction_id,
            collection,
            new_transaction["webhookUrl"]
        )

    return {
        "id": new_transaction["id"],
        "customerName": new_transaction["customerName"],
        "amount": new_transaction["amount"],
        "currency": new_transaction["currency"],
        "status": new_transaction["status"],
        "created": new_transaction["createdAt"]
    }

# ------------------------------------------------------------
# Other endpoints (GET /payments/all, /query, /{transaction_id}, /status)
# remain unchanged from your original file
# ------------------------------------------------------------
