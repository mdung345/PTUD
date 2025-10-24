"""Type hints for MongoDB documents used in the application."""

from datetime import datetime
from typing import Optional, TypedDict

from bson import ObjectId


class UserDocument(TypedDict, total=False):
    _id: ObjectId
    email: Optional[str]
    phone_number: Optional[str]
    hashed_password: str
    created_at: datetime


class DescriptionDocument(TypedDict, total=False):
    _id: ObjectId
    user_id: Optional[ObjectId]
    timestamp: datetime
    source: str
    style: str
    content: str
    image_path: Optional[str]


class PasswordResetTokenDocument(TypedDict, total=False):
    _id: ObjectId
    user_id: ObjectId
    token_hash: str
    created_at: datetime
    expires_at: datetime
    used: bool
