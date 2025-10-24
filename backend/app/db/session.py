"""MongoDB connection utilities and helpers."""

from typing import Optional

from pymongo import ASCENDING, DESCENDING, MongoClient
from pymongo.database import Database

from ..config import get_settings

settings = get_settings()

_client: Optional[MongoClient] = None


def get_client() -> MongoClient:
    global _client
    if _client is None:
        _client = MongoClient(settings.mongodb_uri)
    return _client


def get_database() -> Database:
    return get_client()[settings.mongodb_db]


def init_db() -> None:
    """Ensure collections and indexes exist."""
    db = get_database()

    users = db.get_collection("users")
    users.create_index("email", unique=True, sparse=True)
    users.create_index("phone_number", unique=True, sparse=True)

    descriptions = db.get_collection("descriptions")
    descriptions.create_index([("user_id", ASCENDING), ("timestamp", DESCENDING)])

    tokens = db.get_collection("password_reset_tokens")
    tokens.create_index("user_id")
    tokens.create_index("created_at")
