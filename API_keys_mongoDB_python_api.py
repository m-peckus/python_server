from fastapi import FastAPI, HTTPException, status, BackgroundTasks, Depends, Header
import time
from datetime import datetime, timezone, timedelta 
import httpx 
import uuid 
from pydantic import BaseModel, Field, validator
from typing import Optional

# --- MongoDB Imports and Configuration ---
import os 
from dotenv import load_dotenv
from pymongo import MongoClient
from pymongo.collection import Collection
from pymongo.errors import ConnectionFailure
from bson.objectid import ObjectId


# --- Load Environment Variables ---
# NOTE: This loads variables from the 'local.env' file.
load_dotenv(dotenv_path='.env')


# --- MongoDB Configuration ---

# Now securely loading the URI from the environment (either OS or local.env file)
MONGO_URI = os.getenv("MONGO_URI") 

if not MONGO_URI:
    # If the MONGO_URI is missing, raise an error immediately.
    print("[DB ERROR] MONGO_URI not found. Check your local.env file.")
    exit(1)

DB_NAME = "payment_gateway_db"
COLLECTION_NAME = "transactions"

# --- MOCK USER AUTHENTICATION DATA ---
# This dictionary simulates the 'users' collection in MongoDB. 
# It maps the client's API Key to their unique internal User ID (ownerId).
MOCK_API_KEYS = {
    # Key : User ID (Owner ID)
    "PK_LIVE_JD_XYZ123": "user_john_doe_123",    # John Doe's Key
    "PK_LIVE_AC_321ZYX": "user_acme_corp_456"   # ACME Corporation's Key
}

# --- Application and Database Setup ---

app = FastAPI()

app_start_time = time.monotonic()

STATUS_WEBHOOK_URL = "https://webhook-test.com/aa8bf046900ab914b82788e3d4df32ca"

# --- MongoDB Initialization ---

try:
    # Attempt to establish connection and verify
    client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=5000)
    client.admin.command('ping')
    mongo_db = client[DB_NAME]
    print(f"[DB] Successfully connected to MongoDB Atlas and database '{DB_NAME}'.")
except ConnectionFailure as e:
    print(f"[DB ERROR] Could not connect to MongoDB Atlas. Check URI, network access, and credentials: {e}")
except Exception as e:
    print(f"[DB ERROR] An unexpected error occurred during MongoDB connection: {e}")

# --- Database Dependency (MongoDB) ---

def get_mongo_collection() -> Collection:
    """Dependency that yields the MongoDB transactions collection."""
    try:
        if 'mongo_db' not in globals():
             raise NameError("Database client is not initialized.")
        return mongo_db[COLLECTION_NAME]
    except NameError as e:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Database client is not initialized: {e}"
        )

# --- REQUIRED: Mock Authentication Dependency ---

def get_current_user_id(x_api_key: str = Header(..., alias="X-API-Key")) -> str:
    """
    Validates the API Key provided in the X-API-Key header.
    Returns the associated ownerId (the user's unique identifier).
    """
    # Look up the provided key in our mock user store
    user_id = MOCK_API_KEYS.get(x_api_key)
    
    if not user_id:
        # If the key is invalid, raise a 401 Unauthorized error
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing X-API-Key. Access denied."
        )
    
    # Return the validated user ID, which becomes the document's 'ownerId'
    return user_id

# --- Pydantic Schema ---

class PaymentCharge(BaseModel):
    customerName: str = Field(..., min_length=1, description="Name of the customer.")
    paymentAmount: float = Field(..., gt=0, description="The amount to charge.")
    currency: str = Field(..., max_length=3, description="Currency code (e.g., USD, EUR).")
    details: Optional[str] = Field(None, description="Optional payment details.") 
    webhookUrl: Optional[str] = Field(None, description="Webhook URL for payment notification.")

    @validator('customerName')
    def name_must_not_be_blank(cls, value):
        if not value.strip():
            raise ValueError('Customer name cannot be empty or contain only whitespace.')
        return value.strip()

# --- Webhook Dispatching (Generic Function) ---

async def dispatch_webhook(url: str, payload: dict):
    """Sends a non-blocking webhook notification to a specified URL."""
    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(
                url,
                json=payload,
                timeout=5.0
            )
            print(f"[WEBHOOK] Sent to {url}. Status: {response.status_code}")
    except httpx.RequestError as exc:
        print(f"[WEBHOOK ERROR] Error sending webhook to {url}: {exc}")


# --- Endpoints ---

# GET /api/v1/status - Check the status of the gateway (Public Endpoint)
@app.get("/api/v1/status")
async def get_gateway_status(
    background_tasks: BackgroundTasks, 
    collection: Collection = Depends(get_mongo_collection)
):
    try:
        total_transactions = collection.count_documents({})
    except Exception as e:
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


# POST /api/v1/payments/charge - Process a new payment (REQUIRES AUTHENTICATION)
@app.post("/api/v1/payments/charge", status_code=status.HTTP_201_CREATED)
async def process_new_payment(
    charge: PaymentCharge, 
    background_tasks: BackgroundTasks, 
    collection: Collection = Depends(get_mongo_collection),
    # AUTHORIZATION STEP: Get the validated user ID from the API Key
    owner_id: str = Depends(get_current_user_id) 
):
    
    transaction_id = f"txn_{uuid.uuid4().hex[:12]}" 
    created_at = datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')

    new_transaction = {
        "id": transaction_id, 
        # CRITICAL: TAG the document with the authenticated user's ID
        "ownerId": owner_id, 
        "customerName": charge.customerName,
        "amount": charge.paymentAmount,
        "currency": charge.currency,
        "details": charge.details or 'No details provided',
        "status": 'succeeded',
        "webhookUrl": charge.webhookUrl, 
        "createdAt": created_at
    }

    # 1. Persist the transaction to the database (MongoDB)
    try:
        collection.insert_one(new_transaction)
    except Exception as e:
        print(f"[DB ERROR] Failed to insert transaction {transaction_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to persist payment data due to a database error."
        )

    print(f"[CHARGE] New transaction created: {transaction_id} for Owner: {owner_id}")

    # 2. Dispatch Webhook (if URL provided)
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


    # 3. Respond with 201 Created 
    return {
        "id": new_transaction["id"],
        "customerName": new_transaction["customerName"],
        "amount": new_transaction["amount"],
        "currency": new_transaction["currency"],
        "status": new_transaction["status"],
        "created": new_transaction["createdAt"]
    }


# GET /api/v1/payments/{transaction_id} - Retrieve a transaction by ID (REQUIRES AUTHORIZATION)
@app.get("/api/v1/payments/{transaction_id}")
async def get_payment_by_id(
    transaction_id: str, 
    collection: Collection = Depends(get_mongo_collection),
    # AUTHORIZATION STEP: Get the validated user ID from the API Key
    owner_id: str = Depends(get_current_user_id) 
):
    # CRITICAL: This MongoDB query enforces data separation by searching for documents
    # that match the transaction ID AND the authenticated user's ID.
    transaction = collection.find_one(
        {
            "id": transaction_id, 
            "ownerId": owner_id 
        }, 
        {"_id": 0} # Exclude the MongoDB ObjectId from the result
    )

    if transaction is None:
        # If the ID is not found, or if it belongs to another user, 404 is returned.
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Transaction ID '{transaction_id}' not found for this user."
        )

    return transaction
