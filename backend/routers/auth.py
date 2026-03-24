import pyotp
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from database import get_db
from models import User
from schemas import (
    UserCreate, UserLogin, UserOut, Token,
    LoginOut, TOTPSetupResponse, TOTPVerifyRequest, TOTPLoginRequest,
)
from auth import (
    hash_password, verify_password, create_access_token, get_current_user,
    create_totp_session_token, verify_totp_session_token,
)

router = APIRouter(prefix="/auth", tags=["Authentication"])


@router.post("/register", response_model=UserOut, status_code=201)
def register(user_data: UserCreate, db: Session = Depends(get_db)):
    if db.query(User).filter(User.email == user_data.email).first():
        raise HTTPException(status_code=400, detail="Email already registered")
    if db.query(User).filter(User.username == user_data.username).first():
        raise HTTPException(status_code=400, detail="Username already taken")
    if len(user_data.password) < 8:
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters")
    user = User(
        email=user_data.email,
        username=user_data.username,
        hashed_password=hash_password(user_data.password),
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


@router.post("/login", response_model=LoginOut)
def login(user_data: UserLogin, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == user_data.username).first()
    if not user or not verify_password(user_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
        )
    if not user.is_active:
        raise HTTPException(status_code=400, detail="Account is disabled")

    # If TOTP is enabled, issue a short-lived session token (challenge)
    if user.totp_enabled and user.totp_secret:
        return LoginOut(
            requires_totp=True,
            totp_session=create_totp_session_token(user.username),
        )

    token = create_access_token({"sub": user.username})
    return LoginOut(access_token=token, token_type="bearer", user=UserOut.model_validate(user))


@router.post("/totp/verify-login", response_model=Token)
def totp_verify_login(body: TOTPLoginRequest, db: Session = Depends(get_db)):
    """Complete 2-step login by verifying the TOTP code."""
    user = verify_totp_session_token(body.totp_session, db)
    totp = pyotp.TOTP(user.totp_secret)
    if not totp.verify(body.code, valid_window=1):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid TOTP code")
    token = create_access_token({"sub": user.username})
    return Token(access_token=token, token_type="bearer", user=user)


@router.post("/totp/setup", response_model=TOTPSetupResponse)
def totp_setup(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Generate a new TOTP secret for the current user (does NOT enable 2FA yet)."""
    if current_user.totp_enabled:
        raise HTTPException(status_code=400, detail="TOTP is already enabled. Disable it first.")
    secret = pyotp.random_base32()
    provisioning_uri = pyotp.TOTP(secret).provisioning_uri(
        name=current_user.username,
        issuer_name="SSTB",
    )
    current_user.totp_secret = secret
    db.commit()
    return TOTPSetupResponse(secret=secret, provisioning_uri=provisioning_uri)


@router.post("/totp/enable")
def totp_enable(
    body: TOTPVerifyRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Verify the first TOTP code and activate 2FA."""
    if current_user.totp_enabled:
        raise HTTPException(status_code=400, detail="TOTP is already enabled")
    if not current_user.totp_secret:
        raise HTTPException(status_code=400, detail="Call /auth/totp/setup first")
    totp = pyotp.TOTP(current_user.totp_secret)
    if not totp.verify(body.code, valid_window=1):
        raise HTTPException(status_code=400, detail="Invalid TOTP code")
    current_user.totp_enabled = True
    db.commit()
    return {"message": "Two-factor authentication enabled successfully"}


@router.post("/totp/disable")
def totp_disable(
    body: TOTPVerifyRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Disable 2FA — requires a valid TOTP code to confirm."""
    if not current_user.totp_enabled:
        raise HTTPException(status_code=400, detail="TOTP is not enabled")
    totp = pyotp.TOTP(current_user.totp_secret)
    if not totp.verify(body.code, valid_window=1):
        raise HTTPException(status_code=400, detail="Invalid TOTP code")
    current_user.totp_enabled = False
    current_user.totp_secret = None
    db.commit()
    return {"message": "Two-factor authentication disabled"}


@router.get("/me", response_model=UserOut)
def get_me(current_user: User = Depends(get_current_user)):
    return current_user
