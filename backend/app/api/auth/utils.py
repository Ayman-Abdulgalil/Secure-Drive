import os
import asyncpg
from fastapi.security import OAuth2PasswordBearer
import jwt, jwt.exceptions as JWTError
from passlib.context import CryptContext
from datetime import datetime, timedelta, timezone
from fastapi import Depends, HTTPException, status

from ...models.user import UserResponse
from ...repositories.database import db
from ...repositories.users import get_user_by_id

# Configuration
_SECRET_KEY = os.environ.get("JWT_SECRET_KEY", "")
_ALGORITHM = os.environ.get("JWT_ALGORITHM", "HS256")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Password hashing
password_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def hash_password(password: str) -> str:
    """Hash a password using bcrypt."""
    return password_context.hash(password)


def verify_password(*, plain_password: str, hashed_password: str) -> bool:
    """Verify a password against its hash."""
    return password_context.verify(plain_password, hashed_password)


def create_access_token(user_id: str) -> tuple[str, datetime]:
    """Create a JWT access token."""
    minutes = int(os.environ.get("ACCESS_TOKEN_EXPIRE_MINUTES", "60"))
    expire_at = datetime.now(timezone.utc) + timedelta(minutes=minutes)
    token = {"sub": str(user_id), "exp": expire_at, "type": "access"}
    assert _SECRET_KEY
    return (jwt.encode(token, _SECRET_KEY, algorithm=_ALGORITHM), expire_at)


# def create_refresh_token(user_id: str, version: int) -> str:
#     """Create a JWT refresh token and return it."""
#     days = int(os.environ.get("REFRESH_TOKEN_EXPIRE_DAYS", "30"))
#     expire_at = datetime.now(timezone.utc) + timedelta(days=days)
#     token = {"sub": str(user_id), "ver": version, "exp": expire_at, "type": "refresh"}
#     assert _SECRET_KEY
#     return jwt.encode(token, _SECRET_KEY, algorithm=_ALGORITHM)


def decode_token(token: str) -> dict | None:
    """Decode and verify a JWT token."""
    try:
        return jwt.decode(token, _SECRET_KEY, algorithms=[_ALGORITHM])
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None


async def get_current_user(
    token: str = Depends(oauth2_scheme), conn: asyncpg.Connection = Depends(db)
) -> UserResponse:

    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    try:
        payload = jwt.decode(token, _SECRET_KEY, algorithms=[_ALGORITHM])
        uuid: str = payload.get("sub")
        if uuid is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception

    user = await get_user_by_id(conn=conn, user_id=uuid)
    if user is None:
        raise credentials_exception
    
    user_response = UserResponse(
        name=str(user["name"]),
        email=user["email"],
        created_at=user["created_at"],
        storage_quota=user["storage_quota"],
        storage_used=user["storage_used"],
    )

    return user_response
