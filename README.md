# Mock Payment Gateway API
**Educational Project — Realistic Payment Flow Simulation**  

The Mock **Payment Gateway API** is a learning-focused project that replicates core functionalities of real-world payment service provider (PSP) systems. It was created to understand and demonstrate:
- How real-world PSP APIs structure endpoints and manage data flow. 
- How secure, role-based authorization and authentication  is implemented  using passwords, JWTs, and API keys.  
- How webhook validation is implemented using cryptographic signatures.  
- How a real database - Mongo DB in this project - stores authentication credentials, authorization data and transaction records to emulate PSP API behavior.  

While it mirrors the structure and behavior of production payment APIs, credit card handling and tokenization are intentionally excluded to simplify implementation and focus on core logic such as authentication, authorization, and payment processing.  

---
 **Features**    

**User Management** — Register, authenticate, and assign user roles (user, merchant, admin, system_admin).  
**JWT Authentication** — Secure access control for protected, admin, and system-level routes.  
**API Key Verification** — Used for payment transactions and webhook calls.  
**Transaction Processing** — Simulates payment creation, retrieval, and deletion.  
**Webhook Simulation** — Demonstrates HMAC SHA-256 signature verification for event authenticity.  
**MongoDB Integration** — Ensures persistent storage of users, API keys, JWT tokens, and transaction records.    

---

**Tech Stack**  

**FastAPI** — Framework for high-performance, async API development.  
**MongoDB** — Database for persistent data management.    
**Python-JOSE** — For JWT encoding and verification.  
**Passlib & bcrypt** — For secure password hashing.  
**Uvicorn** — ASGI server for local and production deployment.  

---
**Authentication Overview**  

The API uses three authentication methods depending on the endpoint type:

| Type                 | Header Key                          | Description                                                                         |
| -------------------- | ----------------------------------- | ----------------------------------------------------------------------------------- |
| **Password-based**   | —                                   | Registers new users and login verification for JWT issuance. |
| **JWT Bearer Token** | `Authorization: Bearer <JWT_TOKEN>` | Grants access to protected, admin, and system operations.                           |
| **API Key**          | `X-API-Key: <USER_API_KEY>`         | Used for payment-related endpoints and webhook verification.                        |

---
All requests should be made to:  

- Live (Base URL): https://mock-payment-api-v7a7.onrender.com  
- Development (Local server): http://127.0.0.1:8000

---
**Key Endpoints**

| Method   | Endpoint                           | Description                       | Auth Required       |
| -------- | ---------------------------------- | --------------------------------- | ------------------- |
| `GET`    | `/api/v1/status`                   | Check API status                  | None                |
| `POST`   | `/api/v1/users/register`           | Register a new user               | Password            |
| `POST`   | `/api/v1/users/login`              | Authenticate user and receive JWT | Password            |
| `PATCH`  | `/api/v1/users/{user_id}/role`     | Update user role                  | JWT                 |
| `GET`    | `/api/v1/protected`                | Access protected route            | JWT                 |
| `GET`    | `/api/v1/admin/dashboard`          | Admin-only route                  | JWT                 |
| `POST`   | `/api/v1/payments/charge`          | Create payment                    | API Key             |
| `GET`    | `/api/v1/payments/all`             | Retrieve all user payments        | API Key             |
| `POST`   | `/api/v1/webhook-receive`          | Receive and validate webhooks     | API Key + Signature |
| `DELETE` | `/api/v1/{resource}/{resource_id}` | Delete user or transaction        | JWT                 |
| `GET`    | `/api/v1/payments/query`           | Filter and sort transactions      | API Key + JWT       |

See full API usage examples in the [api_documentation.md](https://github.com/m-peckus/python_server/blob/main/api_documentation.md) file.

---
**Example Use Case**  

A merchant registers and receives an API key and webhook secret.
They then use the API to:
Authenticate with a password to obtain a JWT.
Send payments using the POST /api/v1/payments/charge endpoint.
Receive webhook notifications when payments are completed.
Manage user roles or transactions through JWT-protected routes.
This setup closely replicates real-world payment workflows between clients and payment gateways.  

**Usage Notes:**  
1. Clone the repository.   
 ```
git clone https://github.com/m-peckus/python_server  
cd python_server 
```
2. Create a virtual environment:  

python3 -m venv venv
source venv/bin/activate

3. Install dependencies:  

pip install -r requirements.txt  

4. Run the server:  

uvicorn test_main:app --reload  

5. Access the API locally:  

http://127.0.0.1:8000  


**Learning Outcomes**  

By completing this project, you’ll understand:  

The flow of authentication and authorization in REST APIs.  
Secure credential management using JWT and API keys.  
Structuring modular, production-style FastAPI projects.  
How real payment APIs handle transactions, webhooks, and user roles.  

**Future Improvements**  

Add support for tokenized payment methods.  
Implement transaction reconciliation and refunds.  
Integrate rate limiting and request logging.  
Extend webhook event types for more realistic simulation.  

Author  

Martynas Peckus  
Educational project for mastering REST API development with FastAPI and MongoDB.  
