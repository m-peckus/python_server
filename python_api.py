# python_api.py
from fastapi import FastAPI, HTTPException
import time
from datetime import datetime, timezone, timedelta 
# ADDITION 1: Import httpx for asynchronous web requests
import httpx 

app = FastAPI()

# Mock database
payments = {}

# Simulate your 'transactions' object and a place to store 'uptime'
transactions = {}


# Store the application start time
app_start_time = time.monotonic()

# ADDITION 2: Define the webhook URL (replace with your actual URL)
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

 # MODIFICATION: Call the webhook function AFTER preparing the response data
    await send_status_webhook(response_data)
    
    # The endpoint returns the status response, which is "200 OK"
    return response_data








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
