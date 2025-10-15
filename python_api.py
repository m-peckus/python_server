# python_api.py

# dependencies
from fastapi import FastAPI, HTTPException, status
import time
from datetime import datetime, timezone, timedelta 
import httpx 
import uuid # For generating unique transaction IDs
from pydantic import BaseModel, Field, validator
from typing import Optional


# --- Pydantic Schema ---
# Define the expected structure of the incoming payment request body

class PaymentCharge(BaseModel):
    customerName: str = Field(...,min_length=1, description="Name of the customer.")
    paymentAmount: float = Field(..., gt=0, description="The amount to charge.")
    currency: str = Field(..., max_length=3, description="Currency code (e.g., USD, EUR).")
    details: Optional[str] = Field(None, description="Optional payment details.") 
    webhookUrl: Optional[str] = Field(None, description="Optional URL for receiving notifications.")

    # Add a custom validator to check for non-whitespace content
    @validator('customerName')
    def name_must_not_be_blank(cls, value):
        # Strip leading/trailing whitespace and check if the result is empty
        if not value.strip():
            raise ValueError('Customer name cannot be empty or contain only whitespace.')
        return value.strip() # Return the stripped value for use in the transaction

app = FastAPI()

# Mock database
payments = {}

# Simulate your 'transactions' object and a place to store 'uptime'
transactions = {}


# Store the application start time
app_start_time = time.monotonic()

# Define the webhook URL
WEBHOOK_URL = "https://webhook-test.com/aa8bf046900ab914b82788e3d4df32ca"

# Function to send the webhook message
async def send_status_webhook(status_data: dict):
    # This task is performed in the background
    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(
                WEBHOOK_URL,
                json=status_data,
                timeout=5.0
            )
            # You can log the webhook response for debugging
            print(f"Webhook sent. Status: {response.status_code}")
    except httpx.RequestError as exc:
        # Log the error if the webhook call fails (e.g., DNS error, timeout)
        print(f"Error sending webhook to {WEBHOOK_URL}: {exc}")


# GET /api/v1/status - Check the status of the gateway
@app.get("/api/v1/status")
async def get_gateway_status():
    total_transactions = len(transactions)

    # Calculate uptime
    uptime_seconds = time.monotonic() - app_start_time
    
    # Calculate restart time using the CORRECT 'timedelta'
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

 # Call the webhook function AFTER preparing the response data
    await send_status_webhook(response_data)
    
    # The endpoint returns the status response, which is "200 OK"
    return response_data


# --- Endpoint: POST /api/v1/payments/charge ---
@app.post("/api/v1/payments/charge", status_code=status.HTTP_201_CREATED) # MODIFICATION: Use POST and 201 Created
async def process_new_payment(charge: PaymentCharge):
    
    # Generate Transaction ID and Timestamp
    # Python's UUID is a robust replacement for an incremental counter in a real-world API
    transaction_id = f"txn_{uuid.uuid4().hex[:12]}" 
    created_at = datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')

    # Data Validation (Handled automatically by FastAPI/Pydantic!)
    # If customerName, paymentAmount, or currency are missing/incorrect, FastAPI automatically 
    # returns a 422 Unprocessable Entity response before this function is even called.

    # Create the transaction record
    new_transaction = {
        "id": transaction_id,
        "customerName": charge.customerName,
        "amount": charge.paymentAmount,
        "currency": charge.currency,
        "details": charge.details or 'No details provided',
        "status": 'succeeded',
        "webhookUrl": charge.webhookUrl,
        "createdAt": created_at
    }

    transactions[transaction_id] = new_transaction

    print(f"[CHARGE] New transaction created: {transaction_id}")

    # Respond with 201 Created and transaction details
    # Only return the data required for the client's confirmation
    return {
        "id": new_transaction["id"],
        "customerName": new_transaction["customerName"],
        "amount": new_transaction["amount"],
        "currency": new_transaction["currency"],
        "status": new_transaction["status"],
        "created": new_transaction["createdAt"]
    }



# This endpoint not used, must be deleted

@app.post("/create_payment")
def create_payment(amount: float, currency: str):
    payment_id = len(payments) + 1
    payments[payment_id] = {"id": payment_id, "amount": amount, "currency": currency, "status": "created"}
    return payments[payment_id]

@app.get("/get_payment/{payment_id}")
def get_payment(payment_id: int):
    if payment_id not in payments:
        raise HTTPException(status_code=404, detail="Payment not found")
    return payments[payment_id]

@app.post("/confirm_payment/{payment_id}")
def confirm_payment(payment_id: int):
    if payment_id not in payments:
        raise HTTPException(status_code=404, detail="Payment not found")
    payments[payment_id]["status"] = "confirmed"
    return payments[payment_id]

@app.delete("/cancel_payment/{payment_id}")
def cancel_payment(payment_id: int):
    if payment_id not in payments:
        raise HTTPException(status_code=404, detail="Payment not found")
    payments[payment_id]["status"] = "cancelled"
    return payments[payment_id]
