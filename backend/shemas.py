from pydantic import BaseModel
from datetime import datetime


class OpravilaSeznam(BaseModel):
    id_opravilo: str


class CistilaSeznam(BaseModel):
    id_cistilo: str


class Uporabniki(BaseModel):
    username: str
    password: str
    email: str
    role: str


class Sredstva(BaseModel):
    user_username: str
    cistila: str
    stevilo: int
    denar: float
    date: datetime

    class Config:
        arbitrary_types_allowed = True


class Evidenca(BaseModel):
    user_username: str
    opravilo: str
    done: bool
    datum: datetime

    class Config:
        arbitrary_types_allowed = True


class Token(BaseModel):
    access_token: str
    token_type: str


class ResetToken(BaseModel):
    token: str
    expiration_time: datetime
    user: str


class LoginUser(BaseModel):
    email: str
    password: str
