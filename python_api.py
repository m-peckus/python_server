# mock_payment_api.py
from fastapi import FastAPI, HTTPException
import time
from datetime import datetime, timezone, timedelta 

app = FastAPI()

# Mock database
payments = {}

# Define the base path (like your API_PREFIX)
#API_PREFIX = "/api/v1"


# Simulate your 'transactions' object and a place to store 'uptime'
# In a real app, this would be a database or a more persistent in-memory store.
# For simplicity, we use a global variable to track a transaction count.
transactions = {}

# Store the application start time (FastAPI/Starlette uses the `time` module for uptime)
# Note: process.uptime() is a Node.js specific function. 
# In Python, we calculate uptime using the system start time or by using Starlette's `state` 
# or by just measuring when this script started.

app_start_time = time.monotonic()


# GET /api/v1/status - Check the status of the gateway
@app.get(f"/api/v1/status")
async def get_gateway_status():
    total_transactions = len(transactions)

    # Calculate uptime
    uptime_seconds = time.monotonic() - app_start_time
    
    # Calculate restart time using the CORRECT 'timedelta'
    last_restart_time = datetime.now(timezone.utc) - timedelta(seconds=uptime_seconds)
    
    return {
        "status": "ok",
        "service": "Mock Payment Gateway",
        "version": "v1.0.0",
        "message": "All systems operational.",
        "metrics": {
            "totalTransactions": total_transactions,
            "lastRestart": last_restart_time.isoformat().replace('+00:00', 'Z')
        }
    }



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
