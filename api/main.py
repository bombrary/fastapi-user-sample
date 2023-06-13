from fastapi import Depends, FastAPI
from .routers import auth

app = FastAPI()

app.include_router(auth.router)
