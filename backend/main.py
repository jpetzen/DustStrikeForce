import shemas
from fastapi import FastAPI, status, HTTPException, Depends
from database_delo import (
    engine, SessionLocal, Base, CistilaSeznam, OpravilaSeznam,
    Uporabniki, Sredstva, Evidenca, ResetToken)
from sqlalchemy.orm import Session, DeclarativeBase, MappedColumn
from sqlalchemy_utils import database_exists, create_database
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from datetime import datetime, timedelta
from jose import JWTError, jwt
from sqlalchemy.exc import IntegrityError
from typing import Dict, Any, List
from sqlalchemy import create_engine
from typing import Union
import logging


# Set up logger
logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)


# Create tables stored in the engine
DB_URL = "postgresql://admin:admin@db:5432/cleanDataset"
engine = create_engine(DB_URL)


if not database_exists(engine.url):
    create_database(engine.url)

logging.info(f"Creating following tables: {Base.metadata.tables.keys()}")
Base.metadata.create_all(bind=engine)
engine.connect()

# JWT token
SECRET_KEY = "b3f6e6b9b7f3d2c7a6f9d4e7c8b5a2f1"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
TOKEN_PREFIX = "Bearer"

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


def create_or_update_item(item_list: List[Any],
                          model_class: DeclarativeBase,
                          item_column: MappedColumn,
                          db: Session) -> None:
    for item in item_list:
        db_item = db.query(model_class).filter_by(**{item_column: item}).first()  # noqa: E501

        if not db_item:
            new_item = model_class(**{item_column: item})
            db.add(new_item)
            db.commit()
            db.refresh(new_item)


# Add initial items to the database

seznam_opravil = ["Kitchen", "Floor", "WC", "Bathroom",
                  "Balcony", "Dining room", "Trash"]


seznam_cistil = ["Floor detergent", "Dish detergen",
                 "Toilet duck", "Stelex", "Arf", "BIO garbage bags",
                 "Garbage bags", "Toilet paper", "Paper towels"]

with SessionLocal() as db:
    create_or_update_item(seznam_opravil, OpravilaSeznam, 'id_opravilo', db)
    create_or_update_item(seznam_cistil, CistilaSeznam, 'id_cistilo', db)

# Run the FastAPI application
app = FastAPI()

# Configure CORS settings
origins = [
    "http://localhost",
    "http://0.0.0.0:8071",
    "http://localhost:8071",
    "http://212.101.137.108:8071",
    "*"
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/")
def read_root():
    return "Dust Force"


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#                         AUTHENTICATION
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~


def create_access_token(data: Dict[str, Any],
                        expires_delta: timedelta = None) -> str:
    """
    Create a new JWT token with the given data and expiration time.
    """
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    access_token = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return access_token


def verify_token(token: str,
                 oauth2_scheme:  Union[OAuth2PasswordBearer,
                                       OAuth2PasswordRequestForm,
                                       Dict[str, str]] = Depends()) -> str:
    """
    Verify the JWT token and return the username.
    """

    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token,
                             SECRET_KEY,
                             algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception

    return username


def authenticate_user(username: str, password: str, db: Session = None):
    """
    Authenticate a user.
    """
    user = db.query(Uporabniki).filter(Uporabniki.username == username).first()
    if not user:
        return False
    if not user.password == password:
        return False
    return user


def authenticate_email(email: str, password: str):
    # Get the database session
    db = SessionLocal()
    try:
        # Query the user from the database
        user = db.query(Uporabniki).filter(Uporabniki.email == email).first()

        # Check if the user exists and the password is correct
        if user and password == user.password:
            token_payload = {
                "sub": user.email,
                "role": user.role,  # Include other relevant claims
                "exp": datetime.utcnow() + timedelta(hours=6)
                # Set expiration time
            }
            secret_key = SECRET_KEY  # Replace with your actual secret key
            token = jwt.encode(token_payload, secret_key, algorithm="HS256")
            return token
    finally:
        db.close()

    return None


@app.post("/auth_user", status_code=status.HTTP_200_OK)
def get_user(form_data: shemas.LoginUser, db: Session = Depends(get_db)):
    """
    API to authenticate user, creates a token for the given user.
    """
    email, password = form_data.email, form_data.password
    user = db.query(Uporabniki).filter(Uporabniki.email == email).first()

    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password"
        )
    # Check if the user exists and the password is correct
    if user and password == user.password:
        token_payload = {
            "sub": user.email,
            "role": user.role,  # Include other relevant claims
            "exp": datetime.utcnow() + timedelta(hours=6)
            # Set expiration time
        }
        secret_key = SECRET_KEY  # Replace with your actual secret key
        token = jwt.encode(token_payload, secret_key, algorithm="HS256")
        return {"token": token}
    else:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password"
        )


@app.post("/sign-up", status_code=status.HTTP_201_CREATED)
def sign_up(user: shemas.Uporabniki,
            db: Session = Depends(get_db)
            ):
    """
    API call to add user to the database.
    """
    # Check if the username is already in use
    existing_username = db.query(Uporabniki).filter(Uporabniki.username == user.username).first()  # noqa: E501
    if existing_username:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username already registered"
        )

    # Check if the email is already in use
    existing_email = db.query(Uporabniki).filter(Uporabniki.email == user.email).first()  # noqa: E501
    if existing_email:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already registered"
        )

    # If username and email are unique, proceed with user registration
    db_user = Uporabniki(username=user.username,
                         email=user.email,
                         password=user.password,
                         role=user.role)
    try:
        db.add(db_user)
        db.commit()
        db.refresh(db_user)

        # Generate JWT token for the new user
        access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        access_token = create_access_token(data={"sub": db_user.username},
                                           expires_delta=access_token_expires)

        return {"user": db_user,
                "access_token": access_token,
                "token_type": "bearer"}

    except IntegrityError as e:
        # Handle any potential integrity errors (e.g., duplicate primary key)
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error occurred during user registration"
        ) from e


# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#                             USERS
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

@app.get("/users/", status_code=status.HTTP_200_OK)
def get_users(db: Session = Depends(get_db)):
    """
    API call to get all users from the database.
    """
    users = db.query(Uporabniki).all()
    return users


@app.get("/users/{username}", status_code=status.HTTP_200_OK)
def get_user_by_username(username: str,
                         db: Session = Depends(get_db)):
    """
    API call to get user by username from the database.
    """
    user = db.query(Uporabniki).filter(Uporabniki.username == username).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    return user


def get_current_user(token: str = Depends(oauth2_scheme)) -> Dict[str, Any]:
    """
    Get the current user from the JWT token.
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return {"username": payload.get("sub"), "role": payload.get("role")}
    except JWTError:
        raise credentials_exception


def get_current_active_user(
        current_user: dict = Depends(get_current_user)) -> Dict[str, Any]:
    """
    Get the current active user from the JWT token.
    """
    if current_user["role"] != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You do not have access to this resource",
        )
    return current_user


@app.delete("/users/{username}", status_code=status.HTTP_200_OK)
def delete_user_by_username(
        username: str,
        db: Session = Depends(get_db),
        current_user: dict = Depends(get_current_active_user)):
    """
    API call to delete user by username from the database.
    """
    if current_user["role"] != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You do not have permission to delete users",
        )
    user = db.query(Uporabniki).filter(Uporabniki.username == username).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    db.delete(user)
    db.commit()
    raise HTTPException(status_code=status.HTTP_200_OK,
                        detail="User deleted successfully")


def get_user_info(token: str = Depends(oauth2_scheme),
                  db: Session = Depends(get_db)) -> Uporabniki:
    """
    Get the user info from the JWT token.
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        user = db.query(Uporabniki).filter(Uporabniki.email == email).first()
        if user is None:
            raise credentials_exception
        return user
    except JWTError:
        raise credentials_exception


@app.get("/get-user-info", response_model=dict)
def read_user_info(current_user: Uporabniki = Depends(get_user_info)):
    """
    User info to dict.
    """
    return {
        "id": current_user.id,
        "username": current_user.username,
        "email": current_user.email,
        "role": current_user.role,
    }


# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#                             EVIDENCA
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

@app.get("/opravila/", status_code=status.HTTP_200_OK)
def get_opravila(db: Session = Depends(get_db)):
    """
    API call to get all `opravila` from the database.
    """
    opravila_db = db.query(OpravilaSeznam).all()
    opravila_list = [opravilo.id_opravilo for opravilo in opravila_db]
    return opravila_list


@app.get("/evidenca/", status_code=status.HTTP_200_OK)
def get_evidenca(db: Session = Depends(get_db)):
    """
    API call to get all `evidenca` from the database.
    """
    evidenca = db.query(Evidenca).all()
    # if evidenca is empty
    if not evidenca:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Evidenca not found")
    return evidenca


@app.get("/evidenca/{username}", status_code=status.HTTP_200_OK)
def get_evidenca_by_username(username: str,
                             db: Session = Depends(get_db)):
    """
    API call to get all inputs for user from the database.
    """
    user = db.query(Uporabniki).filter(Uporabniki.username == username).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    evidenca = db.query(Evidenca).filter(
        Evidenca.user_username == username).all()
    return evidenca


@app.post("/evidenca", status_code=status.HTTP_201_CREATED)
def add_evidenca(evidenca: shemas.Evidenca,
                 db: Session = Depends(get_db)):
    """
    API call to add new input for user to the database.
    """
    user = db.query(Uporabniki).filter(
        Uporabniki.username == evidenca.user_username).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    opravilo_instance = db.query(OpravilaSeznam).filter(
        OpravilaSeznam.id_opravilo == evidenca.opravilo).first()

    db_evidenca = Evidenca(
        user_username=evidenca.user_username,
        done=evidenca.done,
        datum=evidenca.datum,
        opravila=opravilo_instance)

    db.add(db_evidenca)
    db.commit()

    return db_evidenca


@app.delete("/evidenca/{id_evidenca}",
            status_code=status.HTTP_200_OK)
def delete_evidenca(id_evidenca: int,
                    db: Session = Depends(get_db)):
    """
    API call to delete `evidenca` for user from the database.
    """
    evidenca = db.query(Evidenca).filter(
        Evidenca.id_evidenca == id_evidenca).first()
    if not evidenca:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Input not found")
    db.delete(evidenca)
    db.commit()
    return {"detail": "Input deleted"}


# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#                             SREDSTVA
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

@app.get("/cistila/", status_code=status.HTTP_200_OK)
def get_cistila(db: Session = Depends(get_db)):
    """
    API call to get all cleaning agents from the database.
    """
    cistila_db = db.query(CistilaSeznam).all()
    cistila_list = [cistilo.id_cistilo for cistilo in cistila_db]
    return cistila_list


@app.post("/sredstva", status_code=status.HTTP_201_CREATED)
def add_sredstva(sredstva: shemas.Sredstva,
                 db: Session = Depends(get_db)):
    """
    API call to add new input for user to the database.
    """
    user = db.query(Uporabniki).filter(
        Uporabniki.username == sredstva.user_username).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    cistilo_instance = db.query(CistilaSeznam).filter(
        CistilaSeznam.id_cistilo == sredstva.cistila).first()

    db_sredstva = Sredstva(
        user_username=sredstva.user_username,
        stevilo=sredstva.stevilo,
        denar=sredstva.denar,
        date=sredstva.date,
        cistilo=cistilo_instance.id_cistilo)

    db.add(db_sredstva)
    db.commit()
    db.refresh(db_sredstva)
    return db_sredstva


@app.get("/sredstva/{username}", status_code=status.HTTP_200_OK)
def get_sredstva(username: str,
                 db: Session = Depends(get_db)):
    """
    API call to get all inputs for user from the database.
    """
    user = db.query(Uporabniki).filter(Uporabniki.username == username).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    sredstva = db.query(Sredstva).filter(
        Sredstva.user_username == username).all()
    return sredstva


@app.delete("/sredstva/{id_sredstva}",
            status_code=status.HTTP_200_OK)
def delete_sredstva(id_sredstva: int,
                    db: Session = Depends(get_db)):
    """
    API call to delete clening agent for user from the database.
    """
    sredstva = db.query(Sredstva).filter(
        Sredstva.id_sredstva == id_sredstva).first()

    if not sredstva:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Input not found")

    db.delete(sredstva)
    db.commit()

    return {"detail": "Input deleted"}


@app.get("/sredstva/", status_code=status.HTTP_200_OK)
def get_all_sredstva(db: Session = Depends(get_db)):
    """
    API call to get all `sredstva` from the database.
    """
    sredstva = db.query(Sredstva).all()
    if not sredstva:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Sredstva not found")
    return sredstva


# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#                            SESSIONS
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

@app.get("/session", status_code=status.HTTP_200_OK)
def get_last_session(db: Session = Depends(get_db)):
    """
    API call to get last session from the database.
    """
    last_session = \
        db.query(ResetToken).order_by(ResetToken.expiration_time).first()

    if last_session is None or \
            last_session.expiration_time < datetime.utcnow():

        return {'token': None,
                'user': None}

    else:
        return {'token': last_session.token,
                'user': last_session.user_username}


@app.post("/clear_session/", status_code=status.HTTP_201_CREATED)
def clear_session(db: Session = Depends(get_db)):
    """
    API call to clear all sessions from the database.
    """
    db.query(ResetToken).delete()
    db.commit()
    return


@app.post("/session_create", status_code=status.HTTP_201_CREATED)
def create_session(session_token: shemas.ResetToken,
                   db: Session = Depends(get_db)):
    """
    API call to create a new session in the database.
    """

    # Create a new session
    new_session = ResetToken(token=session_token.token,
                             expiration_time=session_token.expiration_time,
                             user_username=session_token.user)

    # Add the new session to the database
    db.add(new_session)
    db.commit()
    return
