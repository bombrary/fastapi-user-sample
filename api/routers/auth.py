from fastapi import APIRouter, Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer
from typing import Annotated
from api.schemas import user as user_schema
from api.cruds import user as user_cruds
from api.models import user as user_model
from settings import Settings, get_settings
from passlib.context import CryptContext
from jose import jwt, JWTError
from api.db import get_db
from sqlalchemy.ext.asyncio import AsyncSession
from datetime import timedelta, datetime
from pydantic import BaseModel


router = APIRouter()

pwt_context = CryptContext(schemes=["bcrypt"], deprecated=["auto"])

oauth2_scheme = OAuth2PasswordBearer(tokenUrl='/token')
oauth2_scheme_if_exists = OAuth2PasswordBearer(tokenUrl='/token', auto_error=False)


class TokenData(BaseModel):
    email: str


@router.post("/register", response_model=user_schema.UserCreateResponse)
async def register(
    user_create: user_schema.UserCreate,
    db: Annotated[AsyncSession, Depends(get_db)]
):
    return await user_cruds.create_user(user_create, pwt_context, db)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwt_context.verify(plain_password, hashed_password)


async def authenticate_user(email: str, password: str, db: AsyncSession):
    # ユーザの存在をチェックする
    user = await user_cruds.get_user_by_email(email, db)
    if user is None:
        return False

    # ユーザのパスワードをチェックする
    if not verify_password(password, user.password):
        return False

    return user


def create_access_token(
        data: dict,
        settings: Settings,
        expires_delta: timedelta | None = None,
):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({'exp': expire})
    encoded_jwt = jwt.encode(to_encode, settings.secret_key, algorithm=settings.algorithm)
    return encoded_jwt


@router.post("/token")
async def login(
        form: Annotated[OAuth2PasswordRequestForm, Depends()],
        db: Annotated[AsyncSession, Depends(get_db)],
        settings: Annotated[Settings, Depends(get_settings)],
):
    # ユーザを認証し、それを返す。
    user = await authenticate_user(form.username, form.password, db)
    if not user:
        raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail='Incorrect username or password',
                headers={'WWW-Authenticate': 'Bearer'},
        )

    # トークンを生成して返す。
    access_token_expires = timedelta(minutes=settings.access_token_expire_minues)
    access_token = create_access_token(
        data={'sub': user.email},
        settings=settings,
        expires_delta=access_token_expires,
    )

    return {'access_token': access_token, 'token_type': 'bearer'}


async def get_current_user(
        token: Annotated[str, Depends(oauth2_scheme)],
        db: Annotated[AsyncSession, Depends(get_db)],
        settings: Annotated[Settings, Depends(get_settings)],
):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail='Could not validate credentials',
        headers={'WWW-Authenticate': 'Bearer'},
    )
    try:
        payload = jwt.decode(token, settings.secret_key, algorithms=[settings.algorithm])
        email: str = payload.get('sub')
        if email is None:
            raise credentials_exception
        token_data = TokenData(email=email)
    except JWTError:
        raise credentials_exception

    user = await user_cruds.get_user_by_email(token_data.email, db)
    if user is None:
        raise credentials_exception
    return user


@router.get('/users/me/', response_model=user_schema.UserCreateResponse)
async def read_users_me(
    current_user: Annotated[user_model.User, Depends(get_current_user)],
):
    print(current_user)
    return current_user


@router.get('/is_logined/')
async def is_logined(token: Annotated[str | None, Depends(oauth2_scheme_if_exists)]):
    is_logined = True if token is not None else False
    return { 'result': is_logined }
