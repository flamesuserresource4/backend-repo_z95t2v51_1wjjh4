import os
import re
import secrets
from datetime import datetime, timedelta, timezone
from typing import List, Optional

from fastapi import FastAPI, HTTPException, Depends, Header
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr
from jose import jwt, JWTError
from passlib.context import CryptContext
from bson import ObjectId
from pymongo.errors import DuplicateKeyError

from database import db, create_document, get_documents

# App and CORS
app = FastAPI(title="Game Store API")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Security setup
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
http_bearer = HTTPBearer()
JWT_SECRET = os.getenv("JWT_SECRET", "supersecret")
JWT_ALG = "HS256"
ACCESS_TOKEN_EXPIRE_HOURS = 24
ADMIN_SETUP_KEY = os.getenv("ADMIN_SETUP_KEY", "")
DEV_MODE = os.getenv("DEV_MODE", "true").lower() == "true"


# Utility functions
class TokenData(BaseModel):
    email: EmailStr
    role: str


def create_access_token(email: str, role: str) -> str:
    to_encode = {
        "sub": email,
        "role": role,
        "exp": datetime.utcnow() + timedelta(hours=ACCESS_TOKEN_EXPIRE_HOURS),
        "iat": datetime.utcnow(),
    }
    return jwt.encode(to_encode, JWT_SECRET, algorithm=JWT_ALG)


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain: str, hashed: str) -> bool:
    try:
        return pwd_context.verify(plain, hashed)
    except Exception:
        return False


def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(http_bearer)):
    token = credentials.credentials
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALG])
        email = payload.get("sub")
        role = payload.get("role", "user")
        if email is None:
            raise HTTPException(status_code=401, detail="Invalid token")
        return TokenData(email=email, role=role)
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")


def require_admin(user: TokenData = Depends(get_current_user)):
    if user.role != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    return user


def ci_regex(value: str):
    return {"$regex": f"^{re.escape(value)}$", "$options": "i"}


# Models
class RegisterRequest(BaseModel):
    name: str
    email: EmailStr
    password: str


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class LoginResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    email: EmailStr
    role: str
    name: str


class GameIn(BaseModel):
    title: str
    description: Optional[str] = None
    platforms: List[str]
    categories: List[str] = []
    price: float
    image_url: Optional[str] = None
    is_active: bool = True


class GameOut(GameIn):
    id: str


class OrderCreate(BaseModel):
    game_id: str
    platform: str
    amount: float
    transaction_id: str
    delivery_email: EmailStr


class OrderOut(BaseModel):
    id: str
    user_email: EmailStr
    game_id: str
    platform: str
    amount: float
    payment_method: str
    transaction_id: str
    delivery_email: EmailStr
    status: str
    expected_delivery_within_hours: int
    fulfilled_at: Optional[datetime]


class ForgotPasswordRequest(BaseModel):
    email: EmailStr


class ResetPasswordRequest(BaseModel):
    email: EmailStr
    code: str
    new_password: str


# Health
@app.get("/")
def read_root():
    return {"message": "Game Store API running"}


@app.get("/test")
def test_database():
    response = {
        "backend": "✅ Running",
        "database": "❌ Not Available",
        "database_url": None,
        "database_name": None,
        "connection_status": "Not Connected",
        "collections": []
    }
    try:
        if db is not None:
            response["database"] = "✅ Connected & Working"
            response["database_url"] = "✅ Set" if os.getenv("DATABASE_URL") else "❌ Not Set"
            response["database_name"] = db.name
            response["connection_status"] = "Connected"
            response["collections"] = db.list_collection_names()
    except Exception as e:
        response["database"] = f"❌ Error: {str(e)[:80]}"
    return response


# Expose schemas file content for viewers
@app.get("/schema")
def get_schema_file():
    try:
        with open("schemas.py", "r") as f:
            return {"content": f.read()}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# Helper: ensure default admin exists and is synchronized with env

def ensure_default_admin(force_update_password: bool = False):
    email = os.getenv("DEFAULT_ADMIN_EMAIL")
    password = os.getenv("DEFAULT_ADMIN_PASSWORD")
    name = os.getenv("DEFAULT_ADMIN_NAME", "Admin")
    if not email or not password:
        return False
    try:
        existing = db["user"].find_one({"email": ci_regex(email)})
        if existing:
            updates = {"role": "admin", "is_active": True, "updated_at": datetime.now(timezone.utc)}
            if force_update_password:
                updates["password_hash"] = hash_password(password)
            db["user"].update_one({"_id": existing["_id"]}, {"$set": updates})
            return True
        else:
            doc = {
                "name": name,
                "email": email,
                "password_hash": hash_password(password),
                "role": "admin",
                "is_active": True,
                "created_at": datetime.now(timezone.utc),
                "updated_at": datetime.now(timezone.utc),
            }
            db["user"].insert_one(doc)
            return True
    except Exception as e:
        print(f"❌ ensure_default_admin error: {e}")
        return False


# Startup bootstrap: create indexes and default admin
@app.on_event("startup")
def bootstrap_default_admin():
    try:
        # Unique indexes (may be case-sensitive depending on server collation)
        db["user"].create_index("email", unique=True)
        db["user"].create_index("name", unique=True)
    except Exception as e:
        print(f"⚠️ Index creation warning: {e}")
    updated = ensure_default_admin(force_update_password=False)
    if updated:
        print("✅ Default admin ensured (no password reset)")


# Auth endpoints
@app.post("/auth/register")
def register(data: RegisterRequest):
    # Basic password rule
    if len(data.password) < 6:
        raise HTTPException(status_code=400, detail="Password must be at least 6 characters")

    # Uniqueness checks (case-insensitive)
    existing_email = db["user"].find_one({"email": ci_regex(str(data.email))})
    if existing_email:
        raise HTTPException(status_code=400, detail="Email already registered")
    existing_name = db["user"].find_one({"name": ci_regex(data.name)})
    if existing_name:
        raise HTTPException(status_code=400, detail="Name already taken")

    doc = {
        "name": data.name,
        "email": str(data.email),
        "password_hash": hash_password(data.password),
        "role": "user",
        "is_active": True,
        "created_at": datetime.now(timezone.utc),
        "updated_at": datetime.now(timezone.utc),
    }
    try:
        db["user"].insert_one(doc)
    except DuplicateKeyError:
        # In case race condition with indexes
        raise HTTPException(status_code=400, detail="Email or name already registered")
    token = create_access_token(email=str(data.email), role="user")
    return LoginResponse(access_token=token, email=str(data.email), role="user", name=data.name)


@app.post("/auth/register-admin")
def register_admin(data: RegisterRequest, x_admin_setup_key: Optional[str] = Header(default=None)):
    if not ADMIN_SETUP_KEY or x_admin_setup_key != ADMIN_SETUP_KEY:
        raise HTTPException(status_code=401, detail="Invalid admin setup key")
    if len(data.password) < 6:
        raise HTTPException(status_code=400, detail="Password must be at least 6 characters")
    existing_email = db["user"].find_one({"email": ci_regex(str(data.email))})
    if existing_email:
        raise HTTPException(status_code=400, detail="Email already registered")
    existing_name = db["user"].find_one({"name": ci_regex(data.name)})
    if existing_name:
        raise HTTPException(status_code=400, detail="Name already taken")

    doc = {
        "name": data.name,
        "email": str(data.email),
        "password_hash": hash_password(data.password),
        "role": "admin",
        "is_active": True,
        "created_at": datetime.now(timezone.utc),
        "updated_at": datetime.now(timezone.utc),
    }
    try:
        db["user"].insert_one(doc)
    except DuplicateKeyError:
        raise HTTPException(status_code=400, detail="Email or name already registered")
    token = create_access_token(email=str(data.email), role="admin")
    return LoginResponse(access_token=token, email=str(data.email), role="admin", name=data.name)


@app.post("/auth/login")
def login(data: LoginRequest):
    input_email = str(data.email)
    # Attempt to find user (case-insensitive)
    user = db["user"].find_one({"email": ci_regex(input_email)})

    # Handle default admin via env: if provided exact env credentials, ensure and issue token
    def_email = os.getenv("DEFAULT_ADMIN_EMAIL")
    def_pass = os.getenv("DEFAULT_ADMIN_PASSWORD")
    if def_email and def_pass and input_email.lower() == def_email.lower() and data.password == def_pass:
        # Ensure DB record and password are synced
        ensure_default_admin(force_update_password=True)
        return LoginResponse(
            access_token=create_access_token(email=def_email, role="admin"),
            email=def_email,
            role="admin",
            name=os.getenv("DEFAULT_ADMIN_NAME", "Admin"),
        )

    # Fallback normal path
    if not user or not verify_password(data.password, user.get("password_hash", "")):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    if not user.get("is_active", True):
        raise HTTPException(status_code=403, detail="Account disabled")
    role = user.get("role", "user")
    token = create_access_token(email=user.get("email"), role=role)
    return LoginResponse(access_token=token, email=user.get("email"), role=role, name=user.get("name", ""))


# Forgot/Reset password

def _generate_reset_code() -> str:
    # 6-digit numeric code
    return f"{secrets.randbelow(1_000_000):06d}"


@app.post("/auth/forgot-password")
def forgot_password(data: ForgotPasswordRequest):
    email = str(data.email)
    user = db["user"].find_one({"email": ci_regex(email)})
    # Always respond success to avoid user enumeration
    code = _generate_reset_code()
    expires_at = datetime.now(timezone.utc) + timedelta(minutes=15)
    if user:
        db["password_reset"].update_one(
            {"email": email.lower()},
            {"$set": {"email": email.lower(), "code": code, "expires_at": expires_at, "created_at": datetime.now(timezone.utc)}},
            upsert=True,
        )
        # TODO: integrate email service to send the code to user's email
    response = {"ok": True, "message": "If the email exists, a reset code has been sent."}
    if DEV_MODE:
        response["debug_code"] = code
    return response


@app.post("/auth/reset-password")
def reset_password(data: ResetPasswordRequest):
    email = str(data.email)
    rec = db["password_reset"].find_one({"email": email.lower()})
    if not rec or rec.get("code") != data.code:
        raise HTTPException(status_code=400, detail="Invalid code")
    if rec.get("expires_at") and rec["expires_at"] < datetime.now(timezone.utc):
        raise HTTPException(status_code=400, detail="Code expired")

    user = db["user"].find_one({"email": ci_regex(email)})
    if not user:
        # For safety, consume the code anyway
        db["password_reset"].delete_one({"_id": rec.get("_id")})
        raise HTTPException(status_code=404, detail="User not found")

    if len(data.new_password) < 6:
        raise HTTPException(status_code=400, detail="Password must be at least 6 characters")

    db["user"].update_one({"_id": user["_id"]}, {"$set": {"password_hash": hash_password(data.new_password), "updated_at": datetime.now(timezone.utc)}})
    db["password_reset"].delete_one({"_id": rec.get("_id")})
    return {"ok": True, "message": "Password reset successful"}


# Games - public
@app.get("/games", response_model=List[GameOut])
def list_games(q: Optional[str] = None, platform: Optional[str] = None):
    query = {"is_active": True}
    if q:
        query["title"] = {"$regex": q, "$options": "i"}
    if platform:
        query["platforms"] = {"$in": [platform]}
    docs = db["game"].find(query).sort("created_at", -1)
    items: List[GameOut] = []
    for d in docs:
        items.append(GameOut(
            id=str(d.get("_id")),
            title=d.get("title"),
            description=d.get("description"),
            platforms=d.get("platforms", []),
            categories=d.get("categories", []),
            price=float(d.get("price", 0)),
            image_url=d.get("image_url"),
            is_active=d.get("is_active", True),
        ))
    return items


@app.get("/games/{game_id}", response_model=GameOut)
def get_game(game_id: str):
    try:
        doc = db["game"].find_one({"_id": ObjectId(game_id)})
    except Exception:
        raise HTTPException(status_code=404, detail="Game not found")
    if not doc:
        raise HTTPException(status_code=404, detail="Game not found")
    return GameOut(
        id=str(doc.get("_id")),
        title=doc.get("title"),
        description=doc.get("description"),
        platforms=doc.get("platforms", []),
        categories=doc.get("categories", []),
        price=float(doc.get("price", 0)),
        image_url=doc.get("image_url"),
        is_active=doc.get("is_active", True),
    )


# Games - admin
@app.post("/admin/games", response_model=GameOut)
def create_game(data: GameIn, _: TokenData = Depends(require_admin)):
    doc = data.model_dump()
    doc.update({
        "created_at": datetime.now(timezone.utc),
        "updated_at": datetime.now(timezone.utc),
    })
    res_id = db["game"].insert_one(doc).inserted_id
    return GameOut(id=str(res_id), **data.model_dump())


@app.put("/admin/games/{game_id}", response_model=GameOut)
def update_game(game_id: str, data: GameIn, _: TokenData = Depends(require_admin)):
    try:
        oid = ObjectId(game_id)
    except Exception:
        raise HTTPException(status_code=404, detail="Game not found")
    update_doc = data.model_dump()
    update_doc["updated_at"] = datetime.now(timezone.utc)
    result = db["game"].update_one({"_id": oid}, {"$set": update_doc})
    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="Game not found")
    return GameOut(id=game_id, **data.model_dump())


@app.delete("/admin/games/{game_id}")
def delete_game(game_id: str, _: TokenData = Depends(require_admin)):
    try:
        oid = ObjectId(game_id)
    except Exception:
        raise HTTPException(status_code=404, detail="Game not found")
    result = db["game"].delete_one({"_id": oid})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Game not found")
    return {"deleted": True}


# Orders
@app.post("/orders", response_model=OrderOut)
def create_order(data: OrderCreate, user: TokenData = Depends(get_current_user)):
    # Validate game and amount
    try:
        game = db["game"].find_one({"_id": ObjectId(data.game_id), "is_active": True})
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid game")
    if not game:
        raise HTTPException(status_code=404, detail="Game not found or inactive")
    expected_amount = float(game.get("price", 0))
    if abs(data.amount - expected_amount) > 0.01:
        raise HTTPException(status_code=400, detail="Amount mismatch with listed price")
    order_doc = {
        "user_email": user.email,
        "game_id": data.game_id,
        "platform": data.platform,
        "amount": data.amount,
        "payment_method": "Nagad",
        "transaction_id": data.transaction_id,
        "delivery_email": data.delivery_email,
        "status": "pending",
        "expected_delivery_within_hours": 2,
        "fulfilled_at": None,
        "created_at": datetime.now(timezone.utc),
        "updated_at": datetime.now(timezone.utc),
    }
    inserted_id = db["order"].insert_one(order_doc).inserted_id
    return OrderOut(
        id=str(inserted_id),
        user_email=user.email,
        game_id=data.game_id,
        platform=data.platform,
        amount=data.amount,
        payment_method="Nagad",
        transaction_id=data.transaction_id,
        delivery_email=data.delivery_email,
        status="pending",
        expected_delivery_within_hours=2,
        fulfilled_at=None,
    )


@app.get("/admin/orders", response_model=List[OrderOut])
def list_orders(_: TokenData = Depends(require_admin)):
    docs = db["order"].find().sort("created_at", -1)
    items: List[OrderOut] = []
    for d in docs:
        items.append(OrderOut(
            id=str(d.get("_id")),
            user_email=d.get("user_email"),
            game_id=d.get("game_id"),
            platform=d.get("platform"),
            amount=float(d.get("amount", 0)),
            payment_method=d.get("payment_method", "Nagad"),
            transaction_id=d.get("transaction_id"),
            delivery_email=d.get("delivery_email"),
            status=d.get("status", "pending"),
            expected_delivery_within_hours=int(d.get("expected_delivery_within_hours", 2)),
            fulfilled_at=d.get("fulfilled_at"),
        ))
    return items


class OrderStatusUpdate(BaseModel):
    status: str


@app.patch("/admin/orders/{order_id}", response_model=OrderOut)
def update_order_status(order_id: str, data: OrderStatusUpdate, _: TokenData = Depends(require_admin)):
    try:
        oid = ObjectId(order_id)
    except Exception:
        raise HTTPException(status_code=404, detail="Order not found")
    update_doc = {
        "status": data.status,
        "updated_at": datetime.now(timezone.utc),
    }
    if data.status == "completed":
        update_doc["fulfilled_at"] = datetime.now(timezone.utc)
    result = db["order"].update_one({"_id": oid}, {"$set": update_doc})
    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="Order not found")
    d = db["order"].find_one({"_id": oid})
    return OrderOut(
        id=str(d.get("_id")),
        user_email=d.get("user_email"),
        game_id=d.get("game_id"),
        platform=d.get("platform"),
        amount=float(d.get("amount", 0)),
        payment_method=d.get("payment_method", "Nagad"),
        transaction_id=d.get("transaction_id"),
        delivery_email=d.get("delivery_email"),
        status=d.get("status", "pending"),
        expected_delivery_within_hours=int(d.get("expected_delivery_within_hours", 2)),
        fulfilled_at=d.get("fulfilled_at"),
    )


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
