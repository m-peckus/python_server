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

import hmac
import hashlib
import json


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
# Loads variables from the '.env' file for secure configuration.
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
    """Dependency that returns the MongoDB transactions collection."""
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


def get_current_user_id(x_api_key: str = Header(..., alias="X-API-Key")) -> str:
    """
    Validates the API Key provided in the X-API-Key header using MongoDB.
    Returns the corresponding user's userId.
    """
    if 'mongo_db' not in globals():
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Database not initialized."
        )

    users_collection = mongo_db["users"]
    user_doc = users_collection.find_one({"apiKey": x_api_key})
    if not user_doc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing X-API-Key. Access denied."
        )

    return user_doc["userId"]


# ============================================================
# 3️⃣  APPLICATION SETUP
# ============================================================

app = FastAPI()
app_start_time = time.monotonic()
STATUS_WEBHOOK_URL = "https://webhook-test.com/aa8bf046900ab914b82788e3d4df32ca"

# ============================================================
# 2️⃣.5️⃣  USER REGISTRATION (Dynamic API Key + Webhook Secret)
# ============================================================

USERS_COLLECTION_NAME = "users"

def get_users_collection() -> Collection:
    """Return MongoDB users collection."""
    try:
        if 'mongo_db' not in globals():
            raise NameError("Database client not initialized.")
        return mongo_db[USERS_COLLECTION_NAME]
    except NameError as e:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Database not initialized: {e}"
        )

# -------------------------------
# Pydantic model
# -------------------------------
class UserRegistration(BaseModel):
    """Schema for user registration input."""
    name: str = Field(..., min_length=2, description="Full name of the user or organization.")
    email: str = Field(..., pattern=r'^[\w\.-]+@[\w\.-]+\.\w+$', description="Valid email address.")
    role: str = Field(default="merchant", description="Role of the user in the system.")  # 👈 NEW FIELD


# -------------------------------
# Helper functions
# -------------------------------
def generate_api_key() -> str:
    """Generate a random API key for a new user."""
    return f"PK_LIVE_{uuid.uuid4().hex[:16].upper()}"

def generate_webhook_secret() -> str:
    """Generate a secure random secret for webhook signing."""
    return f"SK_{uuid.uuid4().hex[:32].upper()}"


# -------------------------------
# Endpoint: User Registration
# -------------------------------
@app.post("/api/v1/users/register", status_code=status.HTTP_201_CREATED)
async def register_user(
    user: UserRegistration,
    users_collection: Collection = Depends(get_users_collection)
):
    """
    Register a new user and automatically assign:
    - API key (for authentication)
    - Webhook secret (for secure webhook signing)
    - Default role ("merchant")
    """
    # Check if user already exists by email
    existing_user = users_collection.find_one({"email": user.email})
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User with this email already exists."
        )

    # Generate userId, API key, and webhook secret
    user_id = f"user_{uuid.uuid4().hex[:12]}"
    api_key = generate_api_key()
    webhook_secret = generate_webhook_secret()
    created_at = datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')

    user_doc = {
        "userId": user_id,
        "name": user.name,
        "email": user.email,
        "apiKey": api_key,
        "webhookSecret": webhook_secret,
        "role": user.role,  # 👈 ADDED FIELD HERE
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
        "webhookSecret": webhook_secret,
        "role": user.role,  # 👈 Include in response
        "createdAt": created_at
    }







# ============================================================
# 4️⃣  DATA MODELS (PYDANTIC SCHEMAS)
# ============================================================

class PaymentCharge(BaseModel):
    """Schema for validating incoming payment charge requests."""
    customerName: str = Field(..., min_length=1, description="Name of the customer.")
    paymentAmount: float = Field(..., gt=0, description="Amount to charge.")
    currency: str = Field(..., max_length=3, description="Currency code (e.g., USD, EUR).")
    details: Optional[str] = Field(None, description="Optional payment details.")
    webhookUrl: Optional[str] = Field(None, description="Webhook URL for notifications.")

    @validator('customerName')
    def name_must_not_be_blank(cls, value):
        """Ensure customer name is not empty or whitespace."""
        if not value.strip():
            raise ValueError('Customer name cannot be empty or whitespace.')
        return value.strip()

# ============================================================
# 5️⃣  UTILITY FUNCTIONS
# ============================================================

def sign_payload(payload: dict, secret: str) -> str:
    """
    Generate a HMAC SHA256 signature for a webhook payload.
    """
    payload_bytes = json.dumps(payload, separators=(',', ':')).encode('utf-8')
    signature = hmac.new(secret.encode('utf-8'), payload_bytes, hashlib.sha256).hexdigest()
    return signature

async def dispatch_secure_webhook(url: str, payload: dict, secret: str):
    """
    Send webhook with HMAC signature in header.
    """
    signature = sign_payload(payload, secret)
    headers = {"X-Signature": signature}

    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(url, json=payload, headers=headers, timeout=5.0)
            print(f"[WEBHOOK] Sent to {url}. Status: {response.status_code}, Signature: {signature}")
    except httpx.RequestError as exc:
        print(f"[WEBHOOK ERROR] Failed to send webhook: {exc}")



async def dispatch_webhook(url: str, payload: dict):
    """Send a non-blocking webhook notification to a given URL."""
    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(url, json=payload, timeout=5.0)
            print(f"[WEBHOOK] Sent to {url}. Status: {response.status_code}")
    except httpx.RequestError as exc:
        print(f"[WEBHOOK ERROR] Failed to send webhook: {exc}")



# ============================================================
# Utility: Complete payment after delay
# ============================================================



async def complete_payment_after_delay(transaction_id: str, collection: Collection, webhook_url: str):
    """Wait 5 seconds, mark payment as completed, and send webhook."""
    await asyncio.sleep(5)  # simulate processing delay

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

        # Fetch the user's webhookSecret from MongoDB
        user_doc = collection.database["users"].find_one({"userId": updated["ownerId"]})
        if user_doc and "webhookSecret" in user_doc:
            secret = user_doc["webhookSecret"]
        else:
            secret = "default_secret"  # fallback (optional)

        # Send signed webhook
        await dispatch_secure_webhook(webhook_url, payload, secret)
        print(f"[BACKGROUND] Transaction {transaction_id} marked as completed and webhook sent securely.")




# ============================================================
# 6️⃣  API ENDPOINTS
# ============================================================

# ------------------------------------------------------------
# GET /api/v1/status
# Public endpoint — checks the status of the payment gateway.
# ------------------------------------------------------------
@app.get("/api/v1/status")
async def get_gateway_status(
    background_tasks: BackgroundTasks, 
    collection: Collection = Depends(get_mongo_collection)
):
    """Return operational status, uptime, and transaction count."""
    try:
        total_transactions = collection.count_documents({})
    except Exception:
        total_transactions = "Unavailable"

    uptime_seconds = time.monotonic() - app_start_time
    last_restart_time = datetime.now(timezone.utc) - timedelta(seconds=uptime_seconds)

    response_data = {
        "status": "ok",
        "service": "Mock Payment Gateway",
        "version": "v1.0.0",
        "message": "All systems operational.",
        "metrics": {
            "totalTransactions": total_transactions,
            "lastRestart": last_restart_time.isoformat().replace('+00:00', 'Z')
        }
    }

    background_tasks.add_task(dispatch_webhook, STATUS_WEBHOOK_URL, response_data)
    return response_data


# ------------------------------------------------------------
# POST /api/v1/payments/charge
# Authenticated endpoint — creates a new payment transaction.
# ------------------------------------------------------------
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
        "status": 'pending',
        "webhookUrl": charge.webhookUrl,
        "createdAt": created_at
    }

    try:
        collection.insert_one(new_transaction)
    except Exception as e:
        print(f"[DB ERROR] Failed to insert transaction {transaction_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Database error while saving transaction."
        )

    print(f"[CHARGE] New transaction created: {transaction_id} (Owner: {owner_id})")

    # Schedule background task for automatic status update + webhook
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
# GET /api/v1/payments/all
# Authenticated endpoint — retrieves all transactions for the user.
# ------------------------------------------------------------
@app.get("/api/v1/payments/all")
async def get_all_user_payments(
    collection: Collection = Depends(get_mongo_collection),
    owner_id: str = Depends(get_current_user_id),
    background_tasks: BackgroundTasks = None
):
    """Retrieve all transactions belonging to the authenticated user."""
    try:
        # Fetch all transactions for this user
        user_transactions = list(
            collection.find({"ownerId": owner_id}, {"_id": 0})
        )
        total_transactions = len(user_transactions)
    except Exception as e:
        print(f"[DB ERROR] Failed to retrieve transactions for {owner_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Database error while retrieving user transactions."
        )

    if total_transactions == 0:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No transactions found for this user."
        )

    response_data = {
        "userId": owner_id,
        "totalTransactions": total_transactions,
        "transactions": user_transactions
    }

    # Placeholder for future webhook integration
    # Example:
    # WEBHOOK_URL = "https://webhook-placeholder.com/user-transactions"
    # background_tasks.add_task(dispatch_webhook, WEBHOOK_URL, response_data)

    print(f"[FETCH ALL] Returned {total_transactions} transactions for user: {owner_id}")
    return response_data


# ------------------------------------------------------------
# GET /api/v1/payments/query
# Authenticated endpoint — retrieves user transactions with optional filtering and sorting.
# ------------------------------------------------------------
@app.get("/api/v1/payments/query")
async def query_user_payments(
    minAmount: Optional[float] = None,
    maxAmount: Optional[float] = None,
    sortBy: Optional[str] = "createdAt",  # Field to sort by
    sortOrder: Optional[str] = "desc",    # 'asc' or 'desc'
    collection: Collection = Depends(get_mongo_collection),
    owner_id: str = Depends(get_current_user_id),
    background_tasks: BackgroundTasks = None
):
    """
    Retrieve transactions for the authenticated user with optional filters:
    - minAmount: minimum paymentAmount to include
    - maxAmount: maximum paymentAmount to include
    - sortBy: field to sort by (default 'createdAt')
    - sortOrder: 'asc' for ascending, 'desc' for descending (default 'desc')
    
    Returns a JSON response containing metadata and the list of transactions.
    """
    # Build MongoDB query
    query = {"ownerId": owner_id}
    
    if minAmount is not None:
        query["amount"] = {"$gte": minAmount}
    if maxAmount is not None:
        query.setdefault("amount", {})["$lte"] = maxAmount

    # Determine sort direction
    sort_direction = -1 if sortOrder.lower() == "desc" else 1

    try:
        user_transactions = list(
            collection.find(query, {"_id": 0}).sort(sortBy, sort_direction)
        )
        total_transactions = len(user_transactions)
    except Exception as e:
        print(f"[DB ERROR] Failed to query transactions for {owner_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Database error while querying user transactions."
        )

    if total_transactions == 0:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No transactions found matching the query for this user."
        )

    response_data = {
        "userId": owner_id,
        "totalTransactions": total_transactions,
        "transactions": user_transactions
    }

    # Placeholder for future webhook integration
    # Example:
    # WEBHOOK_URL = "https://webhook-placeholder.com/user-transactions-query"
    # background_tasks.add_task(dispatch_webhook, WEBHOOK_URL, response_data)

    print(f"[QUERY] Returned {total_transactions} transactions for user: {owner_id} (filters applied)")
    return response_data




# ------------------------------------------------------------
# GET /api/v1/payments/{transaction_id}
# Authenticated endpoint — fetches transaction details by ID.
# ------------------------------------------------------------
@app.get("/api/v1/payments/{transaction_id}")
async def get_payment_by_id(
    transaction_id: str,
    collection: Collection = Depends(get_mongo_collection),
    owner_id: str = Depends(get_current_user_id)
):
    """Retrieve a transaction by ID for the authenticated user."""
    transaction = collection.find_one(
        {"id": transaction_id, "ownerId": owner_id},
        {"_id": 0}
    )

    if transaction is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Transaction '{transaction_id}' not found for this user."
        )

    return transaction

# ============================================================
# 🔒 SECURE WEBHOOK RECEIVER ENDPOINT
# ============================================================

from fastapi import Header, HTTPException, status

def verify_webhook_signature(payload: dict, signature: str, secret: str):
    """
    Verifies that the incoming webhook signature matches the payload.
    Raises HTTPException if verification fails.
    """
    import hmac
    import hashlib
    import json

    payload_bytes = json.dumps(payload, separators=(',', ':')).encode('utf-8')
    expected_signature = hmac.new(secret.encode('utf-8'), payload_bytes, hashlib.sha256).hexdigest()

    if not hmac.compare_digest(signature, expected_signature):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid webhook signature"
        )

@app.post("/api/v1/webhook-receive")
async def receive_webhook(payload: dict, x_signature: str = Header(...), x_api_key: str = Header(...)):
    """
    Receives webhooks and validates signature using the user's webhook secret.
    - payload: JSON body sent from your payment service.
    - x_signature: HMAC signature sent in header.
    - x_api_key: User's API key to identify which secret to use.
    """
    # 1️⃣ Retrieve the user's webhook secret from MongoDB
    users_collection = mongo_db["users"]
    user_doc = users_collection.find_one({"apiKey": x_api_key})
    if not user_doc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid X-API-Key"
        )

    secret = user_doc.get("webhookSecret")
    if not secret:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Webhook secret not set for this user"
        )

    # 2️⃣ Verify the signature
    verify_webhook_signature(payload, x_signature, secret)

    # 3️⃣ Process payload safely
    print(f"[WEBHOOK RECEIVED] Verified payload for user {user_doc['userId']}: {payload}")
    return {"status": "verified"}


