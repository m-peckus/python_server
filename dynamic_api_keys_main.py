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

# --- Mock API Key Store ---
# Simulates user records with unique API keys and owner IDs.
#MOCK_API_KEYS = {
#   "PK_LIVE_JD_XYZ123": "user_john_doe_123",    # John Doe's Key
#   "PK_LIVE_AC_321ZYX": "user_acme_corp_456"    # ACME Corporation's Key
#}

def get_current_user_id(x_api_key: str = Header(..., alias="X-API-Key")) -> str:
    """
    Validates the API Key provided in the X-API-Key header.
    First checks MongoDB (dynamic users), then falls back to mock keys.
    Returns the corresponding user's userId.
    """
    # 1️⃣ Check if database is initialized
    if 'mongo_db' in globals():
        users_collection = mongo_db["users"]
        user_doc = users_collection.find_one({"apiKey": x_api_key})
        if user_doc:
            return user_doc["userId"]

    # 2️⃣ Fallback for hardcoded mock users
    user_id = MOCK_API_KEYS.get(x_api_key)
    if user_id:
        return user_id

    # 3️⃣ If no match found, reject request
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or missing X-API-Key. Access denied."
    )

    return user_id

# ============================================================
# 3️⃣  APPLICATION SETUP
# ============================================================

app = FastAPI()
app_start_time = time.monotonic()
STATUS_WEBHOOK_URL = "https://webhook-test.com/aa8bf046900ab914b82788e3d4df32ca"


# ============================================================
# 2️⃣.5️⃣  USER REGISTRATION (Dynamic API Key Generation)
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

class UserRegistration(BaseModel):
    """Schema for user registration input."""
    name: str = Field(..., min_length=2, description="Full name of the user or organization.")
    email: str = Field(..., pattern=r'^[\w\.-]+@[\w\.-]+\.\w+$', description="Valid email address.")

def generate_api_key() -> str:
    """Generate a random API key for a new user."""
    return f"PK_LIVE_{uuid.uuid4().hex[:16].upper()}"

@app.post("/api/v1/users/register", status_code=status.HTTP_201_CREATED)
async def register_user(
    user: UserRegistration,
    users_collection: Collection = Depends(get_users_collection)
):
    """
    Register a new user and automatically assign an API key.
    Returns the generated API key upon successful registration.
    """
    # Check if user already exists by email
    existing_user = users_collection.find_one({"email": user.email})
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User with this email already exists."
        )

    # Generate userId and API key
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

async def dispatch_webhook(url: str, payload: dict):
    """Send a non-blocking webhook notification to a given URL."""
    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(url, json=payload, timeout=5.0)
            print(f"[WEBHOOK] Sent to {url}. Status: {response.status_code}")
    except httpx.RequestError as exc:
        print(f"[WEBHOOK ERROR] Failed to send webhook: {exc}")

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
    """Process a new payment and record it in MongoDB."""
    transaction_id = f"txn_{uuid.uuid4().hex[:12]}"
    created_at = datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')

    new_transaction = {
        "id": transaction_id,
        "ownerId": owner_id,
        "customerName": charge.customerName,
        "amount": charge.paymentAmount,
        "currency": charge.currency,
        "details": charge.details or 'No details provided',
        "status": 'succeeded',
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

    # Optional webhook dispatch
    if new_transaction["webhookUrl"]:
        webhook_payload = {
            "event": "payment.succeeded",
            "id": new_transaction["id"],
            "timestamp": new_transaction["createdAt"],
            "data": {
                "customerName": new_transaction["customerName"],
                "amount": new_transaction["amount"],
                "currency": new_transaction["currency"]
            }
        }
        background_tasks.add_task(dispatch_webhook, new_transaction["webhookUrl"], webhook_payload)

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



