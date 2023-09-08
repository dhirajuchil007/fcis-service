from fastapi import FastAPI, Depends, HTTPException, Header, status
from sqlalchemy import create_engine, Column, String, Integer
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.exc import IntegrityError
from pydantic import BaseModel
from fastapi.security import OAuth2PasswordBearer
import bcrypt
import jwt
from jose import JWTError, jwt
from typing import Any, Union, Optional
from sqlalchemy.types import Time

# Replace this secret key with a long, secure, and random string in your production environment
SECRET_KEY = "thisisasecret"
ALGORITHM = "HS256"

# Replace 'DATABASE_URL' with your actual database connection string
DATABASE_URL = "postgresql://postgres:abc123@localhost/queue_management"
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# DB creation
Base = declarative_base()


# Tables
class Staff(Base):
    __tablename__ = "staff"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, index=True)
    username = Column(String, unique=True, index=True)
    password = Column(String)
    branch = Column(String)
    contact = Column(String)
    role_type = Column(Integer)

class RoleType(Base):
    __tablename__ = "role_type"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String)

Base.metadata.create_all(bind=engine)

#--------------------------------------------------------
#FastAPI start



app = FastAPI()

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/token")


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


class StaffModel(BaseModel):
    name: str
    username: str
    password: str
    branch: str
    contact: str
    role_type: int

class RoleType(BaseModel):
    name:str


def get_current_staff(token: str = Depends(oauth2_scheme)) -> Union[str, Any]:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        return {"username": username, "name": payload.get("name")}
    except JWTError:
        raise credentials_exception


@app.post("/createStaff/")
def create_staff(staff: StaffModel, db: Session = Depends(get_db)):
    try:
        hashed_password = bcrypt.hashpw(staff.password.encode("utf-8"), bcrypt.gensalt())
        decoded_password = hashed_password.decode('utf-8')
        db_staff = Staff(name=staff.name, username=staff.username, password=decoded_password,
                         branch=staff.branch, contact=staff.contact, role_type=staff.role_type,
                        )
        db.add(db_staff)
        db.commit()
        db.refresh(db_staff)
        return "Success"
    except IntegrityError:
        raise HTTPException(status_code=400, detail="Username already exists")


@app.post("/login/")
def login_staff(username: str, password: str, db: Session = Depends(get_db)):
    staff = db.query(Staff).filter(Staff.username == username).first()
    if not staff or not bcrypt.checkpw(password.encode("utf-8"), staff.password.encode("utf-8")):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    token_payload = {"sub": staff.username, "name": staff.name}
    token = jwt.encode(token_payload, SECRET_KEY, algorithm=ALGORITHM)

    return {"user_details":staff,"token":token}


@app.get("/getStaffDetails")
def get_details(payload: dict = Depends(get_current_staff), db: Session = Depends(get_db)):
    staff = db.query(Staff).filter(payload.get("username") == Staff.username).first()
    if staff:
        staff.password = None
    return staff
