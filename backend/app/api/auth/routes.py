import asyncpg
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import HTMLResponse

from ...models.token import LoginResponse
from ...repositories.database import db
from ...repositories.users import (
    create_user,
    mark_verified,
    get_user_by_email,
    record_login,
)
from .email_verification import (
    send_email,
    create_token,
    validate_token,
)
from ...models.user import (
    UserRegister,
    UserLogin,
    UserResponse,
)
from .utils import (
    hash_password,
    verify_password,
    create_access_token,
    get_current_user
    # create_refresh_token,
)

router = APIRouter(prefix="/auth", tags=["Authentication"])


@router.post(
    "/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED
)
async def register(user_data: UserRegister, conn: asyncpg.Connection = Depends(db)):
    try:
        new_user: asyncpg.Record = await create_user(
            conn=conn,
            email=user_data.email,
            password_hash=hash_password(user_data.password),
            name=user_data.name,
        )
    except asyncpg.UniqueViolationError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Email already exists: " + exc.args[0],
        )
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Unexpected error: " + exc.args[0],
        )

    # Attempt to send verification email after the user is persisted
    try:
        send_email(
            recipient=new_user["email"],
            signed_token=create_token(
                new_user["user_id"],
            ),
        )
    except Exception as exc:
        # Email verification link was not sent — don't roll back, just warn the caller
        print(
            f"Warning: Failed to send verification email to {new_user['email']}: {exc}"
        )
        raise HTTPException(
            status_code=status.HTTP_201_CREATED,
            detail="Failed to send verification email: " + exc.args[0],
        )

    return UserResponse(
        name=new_user["name"],
        email=new_user["email"],
        created_at=new_user["created_at"],
        storage_used=new_user["storage_used"],
        storage_quota=new_user["storage_quota"],
    )


@router.post("/resend-verification", status_code=status.HTTP_200_OK)
async def resend_verification(email: str, conn: asyncpg.Connection = Depends(db)):
    # Find user by email
    user: asyncpg.Record = await get_user_by_email(conn=conn, email=email)

    # Attempt to send verification email after the user is persisted
    try:
        send_email(
            recipient=user["email"],
            signed_token=create_token(
                user["user_id"],
            ),
        )
    except Exception as exc:
        # Email verification link was not sent — don't roll back, just warn the caller
        print(f"Warning: Failed to send verification email to {user['email']}: {exc}")
        raise HTTPException(
            status_code=status.HTTP_201_CREATED,
            detail="Failed to send verification email: " + exc.args[0],
        )


@router.get("/verify/{signed_token}", status_code=status.HTTP_200_OK)
async def verify_email(
    signed_token: str,
    conn: asyncpg.Connection = Depends(db),
):
    verification_result = validate_token(signed_token=signed_token)
    await mark_verified(
        conn=conn,
        user_id=verification_result.user_id,
    )

    return HTMLResponse(content='<script>window.location.href="/login"</script>')


@router.post("/login", response_model=LoginResponse, status_code=status.HTTP_200_OK)
async def login(credentials: UserLogin, conn: asyncpg.Connection = Depends(db)):
    # Find user by email
    user: asyncpg.Record = await get_user_by_email(conn=conn, email=credentials.email)

    if not user or not verify_password(
        plain_password=credentials.password, hashed_password=str(user["password_hash"])
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
        )

    if not user["verified"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Email not verified. Please check your inbox for verification instructions.",
        )

    # Update last login
    await record_login(conn=conn, user_id=user["user_id"])

    # Create tokens
    access_token, exp = create_access_token(str(user["user_id"]))

    return LoginResponse(
        access_token=access_token,
        expires_in=int(exp.timestamp()),
    )


# @router.post("/refresh", response_model=LoginResponse)
# async def refresh(
#     token_data: RefreshTokenRequest, db: Annotated[Session, Depends(get_db)]
# ):
#     """
#     Refresh an access token using a refresh token.
#     """
#     # Decode refresh token
#     payload = decode_token(token_data.refresh_token)
#     if not payload or payload.get("type") != "refresh":
#         raise HTTPException(
#             status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid refresh token"
#         )

#     # Check if token exists in database and is not revoked
#     token_hash = hash_token(token_data.refresh_token)
#     stored_token = (
#         db.query(RefreshToken)
#         .filter(RefreshToken.token_hash == token_hash, RefreshToken.revoked.is_(False))
#         .first()
#     )

#     if stored_token is None:
#         raise HTTPException(
#             status_code=status.HTTP_401_UNAUTHORIZED,
#             detail="Refresh token not found or revoked",
#         )

#     # Check if token is expired
#     if stored_token.expires_at < datetime.now(timezone.utc):  # type: ignore
#         raise HTTPException(
#             status_code=status.HTTP_401_UNAUTHORIZED, detail="Refresh token expired"
#         )

#     # Get user
#     user = db.query(User).filter(User.user_id == stored_token.user_id).first()
#     if not user:
#         raise HTTPException(
#             status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found"
#         )

#     # Create new tokens
#     access_token = create_access_token(str(user.user_id))
#     new_refresh_token, refresh_expires = create_refresh_token(str(user.user_id))

#     # Revoke old refresh token and create new one
#     stored_token.revoked = True  # type: ignore
#     new_refresh_token_record = RefreshToken(
#         user_id=user.user_id,
#         token_hash=hash_token(new_refresh_token),
#         expires_at=refresh_expires,
#     )
#     db.add(new_refresh_token_record)
#     db.commit()

#     return LoginResponse(
#         access_token=access_token,
#         refresh_token=new_refresh_token,
#         expires_in=ACCESS_TOKEN_EXPIRE_MINUTES * 60,
#     )


# @router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
# async def logout(
#     token_data: RefreshTokenRequest,
#     current_user: CurrentUser,
#     db: Annotated[Session, Depends(get_db)],
# ):
#     """
#     Logout by revoking refresh token(s).
#     """
#     if token_data and token_data.refresh_token:
#         # Revoke specific token
#         token_hash = hash_token(token_data.refresh_token)
#         db.query(RefreshToken).filter(
#             RefreshToken.token_hash == token_hash,
#             RefreshToken.user_id == current_user.user_id,
#         ).update({"revoked": True})
#     else:
#         # Revoke all tokens
#         db.query(RefreshToken).filter(
#             RefreshToken.user_id == current_user.user_id,
#             RefreshToken.revoked.is_(False),
#         ).update({"revoked": True})

#     db.commit()
#     return None


@router.get("/me", response_model=UserResponse, status_code=status.HTTP_200_OK)
async def get_current_user_info(current_user: UserResponse = Depends(get_current_user)):
    """
    Get current authenticated user information.
    """
    return current_user
