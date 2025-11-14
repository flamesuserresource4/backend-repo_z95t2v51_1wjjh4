"""
Database Schemas for Game Store

Each Pydantic model represents a collection in your MongoDB database.
The collection name is the lowercase of the class name.

Collections:
- user
- game
- order
"""

from pydantic import BaseModel, Field, EmailStr
from typing import Optional, List
from datetime import datetime


class User(BaseModel):
    """
    Users collection schema
    Collection: "user"
    """
    name: str = Field(..., description="Full name")
    email: EmailStr = Field(..., description="Unique email address")
    password_hash: str = Field(..., description="Password hash (not plain text)")
    role: str = Field("user", description="Role: user or admin")
    is_active: bool = Field(True, description="Whether user is active")


class Game(BaseModel):
    """
    Games collection schema
    Collection: "game"
    """
    title: str = Field(..., description="Game title")
    description: Optional[str] = Field(None, description="Game description")
    platforms: List[str] = Field(default_factory=list, description="Platforms e.g., PC, Android, iOS")
    categories: List[str] = Field(default_factory=list, description="Genres/categories")
    price: float = Field(..., ge=0, description="Price in BDT")
    image_url: Optional[str] = Field(None, description="Cover image URL")
    is_active: bool = Field(True, description="Whether the game is visible for sale")


class Order(BaseModel):
    """
    Orders collection schema
    Collection: "order"
    """
    user_email: EmailStr = Field(..., description="Customer email")
    game_id: str = Field(..., description="Purchased game _id as string")
    platform: str = Field(..., description="Selected platform")
    amount: float = Field(..., ge=0, description="Amount paid in BDT")
    payment_method: str = Field("Nagad", description="Payment method (Nagad send money)")
    transaction_id: str = Field(..., description="Nagad transaction ID")
    delivery_email: EmailStr = Field(..., description="Email to receive game/license")
    status: str = Field("pending", description="Order status: pending, processing, completed, cancelled")
    expected_delivery_within_hours: int = Field(2, description="Expected fulfillment window in hours")
    fulfilled_at: Optional[datetime] = Field(None, description="When order was completed")
