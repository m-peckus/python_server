#  Mock Payment Gateway API — Reference Documentation

**Version:** v1.0.0  
**Environment:** Live testing (deployed instance)  
**Base URL:** `https://mock-payment-api-v7a7.onrender.com`  
**Notes:** Replace placeholders such as `<JWT_TOKEN>`, `<SYSTEM_ADMIN_JWT>`, `<USER_API_KEY>` with actual values when using the API.

---

## Table of Contents  

- [Overview](#overview)  
- [Authentication](#authentication)  
- [Endpoints](#endpoints)  
   - [GET /api/v1/status](#get-apiv1status)
   - [POST /api/v1/users/register](#post-apiv1usersregister)  
   - [POST /api/v1/users/login](#post-apiv1userslogin)  
   - [PATCH /api/v1/users/{user_id}/role](#patch-apiv1usersuser_idrole)  
   - [GET /api/v1/protected](#get-apiv1protected)  
   - [GET /api/v1/admin/dashboard](#get-apiv1admindashboard)  
   - [POST /api/v1/payments/charge](#post-apiv1paymentscharge)  
   - [GET /api/v1/payments/all](#get-apiv1paymentsall)  
   - [POST /api/v1/webhook-receive](#post-apiv1webhook-receive)  
   - [DELETE /api/v1/{resource}/{resource_id}](#delete-apiv1resourceresource_id)  
   - [GET /api/v1/payments/query](#get-apiv1paymentsquery)

---

##  Overview  

The Mock **Payment Gateway API** is an educational project designed to simulate a real-world payment platform environment. It provides endpoints for user registration, authentication, role management, transaction processing, and webhook verification. Credit card handling and tokenization are intentionally excluded to simplify implementation and keep the focus on core payment logic. The API is connected to MongoDB for persistent data storage, closely reflecting how real PSP systems manage user credentials, API keys, tokens, and transaction records.      

All requests should be made to:

- Development (local server): http://127.0.0.1:8000  
- Live (deployed instance): https://mock-payment-api-v7a7.onrender.com


---

## Authentication  

This API supports three authentication methods depending on the endpoint:

| Type | Header Key | Description |
|------|-------------|-------------|
| **Password-based authentication** | —   | Used during user registration and authenticate existing users prior to JWT generation |
| **JWT Bearer Token** | `Authorization: Bearer <JWT_TOKEN>` | Used for protected, admin, and system operations |
| **API Key** | `X-API-Key: <USER_API_KEY>` | Used for payment-related endpoints and webhook calls |

---

## Endpoints  

---

## `GET /api/v1/status`  

**Description:** Check API status.  
**Authentication:** None.

**Request:**
```
bash

curl -X GET "https://mock-payment-api-v7a7.onrender.com/api/v1/status"

```
**Sample Response:**  

```
json

{
    "status": "ok",
    "service": "Mock Payment Gateway",
    "version": "v1.0.0",
    "message": "All systems operational.",
    "metrics": {
        "totalTransactions": 42,
        "lastRestart": "2025-11-05T10:45:00Z"
    }
}
```
## `POST /api/v1/users/register`  

**Description:** Register a new user (default role: user).  
**Authentication:** Password.

**Request:**
```
bash

curl -X POST "https://mock-payment-api-v7a7.onrender.com/api/v1/users/register" \
-H "Content-Type: application/json" \
-d '{
    "name": "Acme Finance",
    "email": "acme@office.com",
    "password": "Password123!#"
}'
```

**Sample Response:**  

```
json

{
    "message": "User registered successfully.",
    "userId": "user_1a2b3c4d5e6f",
    "apiKey": "PK_LIVE_1A2B3C4D5E6F7G8H",
    "webhookSecret": "SK_9A8B7C6D5E4F3G2H1I0J",
    "role": "user",
    "createdAt": "2025-11-05T10:45:00Z"
}
```

## `POST /api/v1/users/login`  

**Description:** Authenticate a user and receive a JWT token.  
**Authentication:**  Password.  

**Request (Regular User):**  

```
bash

curl -X POST "https://mock-payment-api-v7a7.onrender.com/api/v1/users/login" \
-H "Content-Type: application/json" \
-d '{
    "email": "acme@office.com",
    "password": "Password123!#"
}'
```
**Request (System Admin):**  

```
bash

curl -X POST "https://mock-payment-api-v7a7.onrender.com/api/v1/users/login" \
-H "Content-Type: application/json" \
-d '{
    "email": "admin@system.local",
    "password": "Admin@123!"
}'
```
**Sample Response:**  
```
json

{
    "access_token": "<JWT_TOKEN>",
    "token_type": "bearer",
    "userId": "user_abcd1234",
    "role": "user"
}
```

## `PATCH /api/v1/users/{user_id}/role` 

**Description:** Update a user’s role. Only system_admin users are allowed.  
**Authentication:** JWT bearer token.  

**Request:**  
```
bash

curl -X PATCH "https://mock-payment-api-v7a7.onrender.com/api/v1/users/{user_id}/role" \
-H "Authorization: Bearer <SYSTEM_ADMIN_JWT>" \
-H "Content-Type: application/json" \
-d '{
    "new_role": "merchant"
}'
```
**Sample Response:**  
```
json

{
    "message": "User role updated to 'ValidRoles.merchant'",
    "userId": "user_f9ac33158ac8"
}
```

**Notes:**  

- Allowed roles: ```user```, ```merchant```, ```admin```

- Only system_admin can perform this operation

- Unauthorized users receive 403 Forbidden


## `GET /api/v1/protected`  

**Description:** Access-protected route for any authenticated user.  
**Authentication:** JWT bearer token.  

**Request:**  
```
bash 

curl -X GET "https://mock-payment-api-v7a7.onrender.com/api/v1/protected" \
-H "Authorization: Bearer <JWT_TOKEN>"
```
**Sample Response:**  
```
json

{
    "message": "Access granted — authenticated user.",
    "userId": "user_1a2b3c4d5e6f",
    "role": "user"
}
```

## `GET /api/v1/admin/dashboard`  

**Description:** Admin-only dashboard.  
**Authentication:** JWT bearer token.  
**Allowed Roles:** ```admin```, ```system_admin```.  

**Request:** 
```
bash

curl -X GET "https://mock-payment-api-v7a7.onrender.com/api/v1/admin/dashboard" \
-H "Authorization: Bearer <ADMIN_JWT>"
```
**Sample Response:**
```
json

{
    "message": "Welcome to the admin dashboard.",
    "userId": "user_abcd1234",
    "role": "admin"
}

```

## `POST /api/v1/payments/charge`  

**Description:** Create a new payment transaction.  
**Authentication:** X-API-Key header.  

**Request:** 
```
bash

curl -X POST "https://mock-payment-api-v7a7.onrender.com/api/v1/payments/charge" \
-H "X-API-Key: <USER_API_KEY>" \
-H "Content-Type: application/json" \
-d '{
    "customerName": "Acme Corporation",
    "paymentAmount": 1000.00,
    "currency": "USD",
    "details": "Payment for order #123",
    "webhookUrl": "https://webhook-test.com/example"
}'
```

**Sample Response:**  
```
json

{
    "id": "txn_abcd1234",
    "customerName": "Acme Corporation",
    "amount": 1000.00,
    "currency": "USD",
    "status": "pending",
    "created": "2025-11-05T10:50:00Z"
}
```

## `GET /api/v1/payments/all`  

**Description:** Retrieve all payments for the authenticated user.  
**Authentication:** X-API-Key header.  

**Request:**  
```
bash

curl -X GET "https://mock-payment-api-v7a7.onrender.com/api/v1/payments/all" \
-H "X-API-Key: <USER_API_KEY>"
```
**Sample Response:**  
```
json
{
  "userId": "user_99e3f6242bce",
  "totalTransactions": 1,
  "transactions": [
    {
      "id": "txn_831e7dbaeadb",
      "ownerId": "user_99e3f6242bce",
      "customerName": "Acme Corporation",
      "amount": 1900.5,
      "currency": "USD",
      "details": "Payment for order #123",
      "status": "completed",
      "webhookUrl": "https://webhook-test.com/example",
      "createdAt": "2025-11-06T11:13:58.910515Z"
    }
  ]
}
```

## `POST /api/v1/webhook-receive`  

**Description:** Receive incoming webhooks and validate HMAC signatures.  
**Authentication:** X-API-Key + X-Signature.  
**Usage Notes:**  
1. Run the generate_curl.py script.  
2. The script:  
- Fetches the user's webhook secret from MongoDB.
- Generates a sample JSON payload (e.g., payment.completed event).
- Creates an HMAC SHA-256 signature of the payload.
- Example output produced by generate_curl.py:    
```
curl -X POST "<BASE_URL>/api/v1/webhook-receive" \
-H "Content-Type: application/json" \
-H "X-API-Key: PK_LIVE_C069A5B0E8F54E05" \
-H "X-Signature: 854611c652b7817ef4b6bdd02ff2812f4671a8bd6274c9c93f05098c5fc15836" \
-d '{"event": "payment.completed", "id": "txn_6147ca82b25e", "data": {"customerName": "Acme Corporation", "amount": 1000.5, "status": "completed"}}'
```
**Purpose:**  
The signature serves as proof of authenticity that the webhook was generated by the authorized system.  

## `DELETE /api/v1/{resource}/{resource_id}`  

**Description:** Delete a transaction or user.  
**Authentication:** JWT bearer token.  
**Notes:**
- Transactions: deletable by owner or system_admin/admin.  
- Users: deletable by system_admin/admin only.  
- Self-deletion is not allowed.  

**Delete Transaction Example:**  
```
bash

curl -X DELETE "https://mock-payment-api-v7a7.onrender.com/api/v1/transactions/{transaction_id}" \
-H "Authorization: Bearer <USER_JWT>"
```
**Delete User Example:**  
```
bash

curl -X DELETE "https://mock-payment-api-v7a7.onrender.com/api/v1/users/{user_id}" \
-H "Authorization: Bearer <SYSTEM_ADMIN_JWT>"
```

## `GET /api/v1/payments/query`  

**Description:** Retrieve user transactions with optional filtering and sorting.  
**Authentication:** X-API-Key header + JWT bearer token (any authenticated user).  
**Examples:**  
1. Retrieve all transactions  
```
bash

curl -X GET "https://mock-payment-api-v7a7.onrender.com/api/v1/payments/query" \
-H "X-API-Key: <USER_API_KEY>" \
-H "Authorization: Bearer <USER_JWT>"
```
2. Filter by amount range  
```
bash

curl -X GET "https://mock-payment-api-v7a7.onrender.com/api/v1/payments/query?minAmount=100&maxAmount=500" \
-H "X-API-Key: <USER_API_KEY>" \
-H "Authorization: Bearer <USER_JWT>"
```
3. Sort results  
```
bash

curl -X GET "https://mock-payment-api-v7a7.onrender.com/api/v1/payments/query?sortBy=amount&sortOrder=asc" \
-H "X-API-Key: <USER_API_KEY>" \
-H "Authorization: Bearer <USER_JWT>"
```
**Sample Response:**  
```
json

{
    "userId": "user_99e3f6242bce",
    "totalTransactions": 2,
    "transactions": [
        {
            "id": "txn_1a2b3c4d5e6f",
            "ownerId": "user_99e3f6242bce",
            "customerName": "Project Falcon",
            "amount": 150.75,
            "currency": "USD",
            "details": "Payment for order #451",
            "status": "completed",
            "createdAt": "2025-11-06T11:13:58.910515Z"
        },
        {
            "id": "txn_7e8f9a0b1c2d",
            "ownerId": "user_99e3f6242bce",
            "customerName": "Project Falcon",
            "amount": 300.25,
            "currency": "USD",
            "details": "Refund for order #552",
            "status": "pending",
            "createdAt": "2025-11-07T09:15:12.110215Z"
        }
    ]
}
```


**Query Parameters:**  
| Parameter   | Description                              | Example          |
| ----------- | ---------------------------------------- | ---------------- |
| `minAmount` | Minimum payment amount                   | `?minAmount=100` |
| `maxAmount` | Maximum payment amount                   | `?maxAmount=500` |
| `sortBy`    | Field to sort by (`amount`, `createdAt`) | `?sortBy=amount` |
| `sortOrder` | Sort order (`asc`, `desc`)               | `?sortOrder=asc` |

**Notes:**  
- If no transactions match filters → returns 404 Not Found.  
- Each user only sees their own transactions.  

