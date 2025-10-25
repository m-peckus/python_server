# top of the file
import hmac
import hashlib
import json
import httpx
from fastapi import Header, HTTPException, status

# replace any existing "dispatch webhook function" (like send_webhook) with:

async def dispatch_secure_webhook(url: str, payload: dict, secret: str):
    ...


# wherever you call the webhook in your code (e.g. after payment completion), replace:

await send_webhook(webhook_url, payload)
#with
await dispatch_secure_webhook(webhook_url, payload, "your_webhook_secret_here")
 # ! the secret can later come from the environment variables or DB

 # At the bottom of the file add the receiver endpoint

 @app.post("/api/v1/webhook-receive")
async def receive_webhook(payload: dict, x_signature: str = Header(...)):
    secret = "your_webhook_secret_here"
    verify_webhook_signature(payload, x_signature, secret)
    print(f"[WEBHOOK RECEIVED] Verified payload: {payload}")
    return {"status": "verified"}


