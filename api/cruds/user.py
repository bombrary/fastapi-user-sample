from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.engine import Result

from api.schemas import user as user_schema
from api.models import user as user_model

from passlib.context import CryptContext


async def create_user(
    user_create: user_schema.UserCreate,
    pwt_context: CryptContext,
    db: AsyncSession,
) -> user_model.User:
    user_create.password = pwt_context.hash(user_create.password)

    user = user_model.User(**user_create.dict())
    db.add(user)
    await db.commit()
    await db.refresh(user)

    return user


async def get_user_by_email(
        email: str,
        db: AsyncSession,
) -> user_model.User | None:
    result: Result = await db.execute(
        select(
            user_model.User
        ).filter(user_model.User.email == email)
    )

    user: Tuple[user_model.User] | None = result.first()

    return user[0] if user is not None else None

