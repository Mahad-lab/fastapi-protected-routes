from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from typing import Union
from datetime import datetime, timedelta
from schema import Token, User
from jose import JWTError, jwt
# import jwt

# Constants for JWT
SECRET_KEY = "238432032984"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

app = FastAPI()

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# functions
def verify_password(plain_password, hashed_password):
    return plain_password == hashed_password  # Replace with a proper hashing check

def get_password_hash(password):
    return password  # Replace with actual hashing logic

def create_access_token(data: dict, expires_delta: Union[timedelta, None] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def authenticate_user(db, username: str, password: str):
    user = db.get(username)
    if not user or not verify_password(password, user['hashed_password']):
        return False
    return user


def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    user = fake_users_db.get(username)
    if user is None:
        raise credentials_exception
    return user

def get_current_active_user(current_user: User = Depends(get_current_user)):
    if current_user["type"] not in ["user", "admin"]:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user

def get_current_active_admin(current_user: User = Depends(get_current_user)):
    if current_user["type"] != "admin":
        raise HTTPException(status_code=400, detail="Not enough permissions")
    return current_user


# temp db   (user of list is better but for simplicity sake)    
fake_users_db = {
    "reg": {
        "type": "user",
        "username": "reg",
        "email": "reg@example.com",
        "hashed_password": get_password_hash("reg"),
    },
    "admin": {
        "type": "admin",
        "username": "admin",
        "email": "admin@example.com",
        "hashed_password": get_password_hash("admin"),
    }
}


# routes
@app.post("/token", response_model=Token)
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(fake_users_db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user["username"]}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}


@app.get("/user")
async def get_user(user_id: int, token: str = Depends(oauth2_scheme), current_user: User = Depends(get_current_active_user)):
    return {"item_id": user_id, "message": "user details"}

@app.post("/user")
async def create_user(user: User, token: str = Depends(oauth2_scheme), current_user: User = Depends(get_current_active_admin)):
    return user
