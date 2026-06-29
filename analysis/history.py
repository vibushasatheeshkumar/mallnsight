import os
from datetime import datetime, timezone

try:
    from pymongo import MongoClient
    from pymongo.errors import PyMongoError
    PYMONGO_AVAILABLE = True
except ImportError:
    PYMONGO_AVAILABLE = False

_client = None
_collection = None
_connection_error = None
_attempted = False


def _get_collection():
    """
    Lazily connect to MongoDB Atlas on first use (env vars are read here,
    not at import time, so this works correctly regardless of when
    load_dotenv() runs relative to this module being imported). Caches
    the connection (or the failure reason) for the lifetime of the
    process.
    """

    global _client, _collection, _connection_error, _attempted

    if _attempted:
        return _collection

    _attempted = True

    if not PYMONGO_AVAILABLE:
        _connection_error = "pymongo is not installed."
        return None

    mongodb_uri = os.environ.get("MONGODB_URI")
    mongodb_db = os.environ.get("MONGODB_DB", "mallnsight")

    if not mongodb_uri:
        _connection_error = "MONGODB_URI is not configured."
        return None

    try:
        _client = MongoClient(mongodb_uri, serverSelectionTimeoutMS=5000)
        _client.admin.command("ping")
        _collection = _client[mongodb_db]["analyses"]
    except PyMongoError as e:
        _connection_error = str(e)
        return None

    return _collection


def _reset_cache():
    """Test-only hook to force the next call to reconnect from scratch."""

    global _client, _collection, _connection_error, _attempted
    _client = None
    _collection = None
    _connection_error = None
    _attempted = False


def is_available():
    _get_collection()
    return _connection_error is None


def get_connection_error():
    _get_collection()
    return _connection_error


def save_analysis(metadata, hashes, score_info):
    """
    Save a summary of one analysis run to MongoDB Atlas.
    Returns the inserted record's id as a string, or None if the
    database isn't configured/reachable (the caller should treat this
    as non-fatal).
    """

    collection = _get_collection()

    if collection is None:
        return None

    record = {
        "filename": metadata.get("name"),
        "size_kb": metadata.get("size"),
        "md5": hashes.get("md5"),
        "sha1": hashes.get("sha1"),
        "sha256": hashes.get("sha256"),
        "risk_score": score_info.get("score"),
        "verdict": score_info.get("verdict"),
        "reasons": score_info.get("reasons", []),
        "analyzed_at": datetime.now(timezone.utc),
    }

    try:
        result = collection.insert_one(record)
        return str(result.inserted_id)
    except PyMongoError:
        return None


def get_recent_analyses(limit=50):
    """
    Return the most recent analysis records, newest first.
    Returns an empty list if the database isn't configured/reachable.
    """

    collection = _get_collection()

    if collection is None:
        return []

    try:
        cursor = collection.find().sort("analyzed_at", -1).limit(limit)
        records = []

        for doc in cursor:
            doc["id"] = str(doc.pop("_id"))
            records.append(doc)

        return records
    except PyMongoError:
        return []
