# # main.py
# from datetime import datetime, timedelta
# from typing import Optional, List

# from fastapi import FastAPI, Depends, HTTPException, status, Body
# from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
# from jose import JWTError, jwt
# from passlib.context import CryptContext
# from sqlmodel import Field, SQLModel, create_engine, Session, select

# import random
# import string

# # === CONFIG ===
# SECRET_KEY = "replace-this-with-a-secure-random-secret"  # change in production
# ALGORITHM = "HS256"
# ACCESS_TOKEN_EXPIRE_MINUTES = 60

# DATABASE_URL = "sqlite:///./proxiattend.db"

# # === DB MODELS ===
# class User(SQLModel, table=True):
#     id: Optional[int] = Field(default=None, primary_key=True)
#     name: str
#     email: str
#     password_hash: str
#     role: str  # "instructor" or "student"
#     bluetooth_id: Optional[str] = None  # optional device identifier
#     created_at: datetime = Field(default_factory=datetime.utcnow)

# class ClassModel(SQLModel, table=True):
#     id: Optional[int] = Field(default=None, primary_key=True)
#     class_name: str
#     instructor_id: int
#     created_at: datetime = Field(default_factory=datetime.utcnow)

# class AttendanceSession(SQLModel, table=True):
#     id: Optional[int] = Field(default=None, primary_key=True)
#     class_id: int
#     instructor_id: int
#     otp: str
#     bluetooth_session_id: Optional[str] = None
#     start_time: datetime = Field(default_factory=datetime.utcnow)
#     end_time: Optional[datetime] = None
#     created_at: datetime = Field(default_factory=datetime.utcnow)

# class AttendanceLog(SQLModel, table=True):
#     id: Optional[int] = Field(default=None, primary_key=True)
#     session_id: int
#     student_id: int
#     check_in_time: datetime = Field(default_factory=datetime.utcnow)
#     check_out_time: Optional[datetime] = None
#     total_class_time: Optional[int] = 0   # minutes
#     total_break_time: Optional[int] = 0   # minutes

# # === DB setup ===
# engine = create_engine(DATABASE_URL, echo=False)
# SQLModel.metadata.create_all(engine)

# # === Auth utils ===
# pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
# oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# def verify_password(plain, hashed):
#     return pwd_context.verify(plain, hashed)

# def get_password_hash(p):
#     return pwd_context.hash(p)

# def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
#     to_encode = data.copy()
#     expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
#     to_encode.update({"exp": expire})
#     return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

# def decode_token(token: str):
#     try:
#         payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
#         return payload
#     except JWTError:
#         return None

# # === FastAPI app ===
# app = FastAPI(title="ProxiAttend Prototype API")

# # === helpers ===
# def get_user_by_email(session: Session, email: str):
#     statement = select(User).where(User.email == email)
#     return session.exec(statement).first()

# def get_user(session: Session, user_id: int):
#     return session.get(User, user_id)

# async def get_current_user(token: str = Depends(oauth2_scheme)):
#     payload = decode_token(token)
#     if not payload:
#         raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
#     user_id = payload.get("sub")
#     if user_id is None:
#         raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token payload")
#     with Session(engine) as db:
#         user = get_user(db, int(user_id))
#         if not user:
#             raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")
#         return user

# def generate_otp(length: int = 6):
#     return "".join(random.choices(string.digits, k=length))

# # === Endpoints ===

# @app.post("/api/auth/register")
# def register(name: str = Body(...), email: str = Body(...), password: str = Body(...), role: str = Body(...), bluetooth_id: Optional[str] = Body(None)):
#     if role not in ("instructor", "student"):
#         raise HTTPException(status_code=400, detail="role must be 'instructor' or 'student'")
#     with Session(engine) as db:
#         if get_user_by_email(db, email):
#             raise HTTPException(status_code=400, detail="Email already registered")
#         user = User(name=name, email=email, password_hash=get_password_hash(password), role=role, bluetooth_id=bluetooth_id)
#         db.add(user)
#         db.commit()
#         db.refresh(user)
#         token = create_access_token({"sub": str(user.id), "role": role})
#         return {"success": True, "userId": user.id, "token": token}


# main.py
from datetime import datetime, timedelta
from typing import Optional, List
from pydantic import BaseModel

from fastapi import FastAPI, Depends, HTTPException, status, Body
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware  # <-- add this import
from jose import JWTError, jwt
from passlib.context import CryptContext
from sqlmodel import Field, SQLModel, create_engine, Session, select

import random
import string

# === CONFIG ===
SECRET_KEY = "replace-this-with-a-secure-random-secret"  # change in production
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

DATABASE_URL = "sqlite:///./proxiattend.db"

# === FastAPI app ===
app = FastAPI(title="ProxiAttend Prototype API")

# === CORS Middleware ===
origins = [
    "http://localhost",
    "http://localhost:19006",   # Expo default port for web testing
    "http://127.0.0.1",
    "http://192.168.29.249",   # Replace with your actual local IP address of your PC
    "*",                       # Or restrict to specific origins in production
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],    # allow all methods (GET, POST, OPTIONS, etc)
    allow_headers=["*"],    # allow all headers
)

# === DB MODELS ===
class User(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    name: str
    email: str
    password_hash: str
    role: str  # "instructor" or "student"
    bluetooth_id: Optional[str] = None  # optional device identifier
    created_at: datetime = Field(default_factory=datetime.utcnow)

class ClassModel(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    class_name: str
    instructor_id: int
    created_at: datetime = Field(default_factory=datetime.utcnow)

class AttendanceSession(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    class_id: int
    instructor_id: int
    otp: str
    bluetooth_session_id: Optional[str] = None
    start_time: datetime = Field(default_factory=datetime.utcnow)
    end_time: Optional[datetime] = None
    created_at: datetime = Field(default_factory=datetime.utcnow)

class AttendanceLog(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    session_id: int
    student_id: int
    check_in_time: datetime = Field(default_factory=datetime.utcnow)
    check_out_time: Optional[datetime] = None
    total_class_time: Optional[int] = 0   # minutes
    total_break_time: Optional[int] = 0   # minutes

# === DB setup ===
engine = create_engine(DATABASE_URL, echo=False)
SQLModel.metadata.create_all(engine)

# === Auth utils ===
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

def verify_password(plain, hashed):
    return pwd_context.verify(plain, hashed)

def get_password_hash(p):
    return pwd_context.hash(p)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def decode_token(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except JWTError:
        return None

# === helpers ===
def get_user_by_email(session: Session, email: str):
    statement = select(User).where(User.email == email)
    return session.exec(statement).first()

def get_user(session: Session, user_id: int):
    return session.get(User, user_id)

async def get_current_user(token: str = Depends(oauth2_scheme)):
    payload = decode_token(token)
    if not payload:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
    user_id = payload.get("sub")
    if user_id is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token payload")
    with Session(engine) as db:
        user = get_user(db, int(user_id))
        if not user:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")
        return user

def generate_otp(length: int = 6):
    return "".join(random.choices(string.digits, k=length))

# === Endpoints ===
@app.post("/api/auth/register")
def register(
    name: str = Body(...),
    email: str = Body(...),
    password: str = Body(...),
    role: str = Body(...),
    bluetooth_id: Optional[str] = Body(None),
):
    if role not in ("instructor", "student"):
        raise HTTPException(status_code=400, detail="role must be 'instructor' or 'student'")
    with Session(engine) as db:
        if get_user_by_email(db, email):
            raise HTTPException(status_code=400, detail="Email already registered")
        user = User(name=name, email=email, password_hash=get_password_hash(password), role=role, bluetooth_id=bluetooth_id)
        db.add(user)
        db.commit()
        db.refresh(user)
        token = create_access_token({"sub": str(user.id), "role": role})
        return {"success": True, "userId": user.id, "token": token}



@app.post("/token")
def login(form_data: OAuth2PasswordRequestForm = Depends()):
    with Session(engine) as db:
        user = get_user_by_email(db, form_data.username)
        if not user or not verify_password(form_data.password, user.password_hash):
            raise HTTPException(status_code=400, detail="Incorrect username or password")
        token = create_access_token({"sub": str(user.id), "role": user.role})
        return {"access_token": token, "token_type": "bearer"}

@app.get("/api/auth/me")
def me(current_user: User = Depends(get_current_user)):
    return {"id": current_user.id, "name": current_user.name, "email": current_user.email, "role": current_user.role}

# Create a class
@app.post("/api/classes")
def create_class(class_name: str = Body(...), student_ids: Optional[List[int]] = Body(None), current_user: User = Depends(get_current_user)):
    if current_user.role != "instructor":
        raise HTTPException(status_code=403, detail="Only instructors can create classes")
    with Session(engine) as db:
        class_row = ClassModel(class_name=class_name, instructor_id=current_user.id)
        db.add(class_row)
        db.commit()
        db.refresh(class_row)
        # (optional) add students later via separate API
        return {"success": True, "classId": class_row.id}

# Start session
# @app.post("/api/sessions/start")
# def start_session(class_id: int = Body(...), current_user: User = Depends(get_current_user)):
#     if current_user.role != "instructor":
#         raise HTTPException(status_code=403, detail="Only instructors can start sessions")
#     otp = generate_otp(6)
#     with Session(engine) as db:
#         session_row = AttendanceSession(class_id=class_id, instructor_id=current_user.id, otp=otp, bluetooth_session_id=f"BT-{random.randint(1000,9999)}")
#         db.add(session_row)
#         db.commit()
#         db.refresh(session_row)
#         return {"success": True, "sessionId": session_row.id, "otp": otp, "bluetoothSessionId": session_row.bluetooth_session_id}

from pydantic import BaseModel

class StartSessionRequest(BaseModel):
    course_id: int

@app.post("/api/sessions/start")
def start_session(request: StartSessionRequest, current_user: User = Depends(get_current_user)):
    if current_user.role != "instructor":
        raise HTTPException(status_code=403, detail="Only instructors can start sessions")
    otp = generate_otp(6)
    with Session(engine) as db:
        session_row = AttendanceSession(
            class_id=request.course_id,
            instructor_id=current_user.id,
            otp=otp,
            bluetooth_session_id=f"BT-{random.randint(1000,9999)}"
        )
        db.add(session_row)
        db.commit()
        db.refresh(session_row)
        return {
            "success": True,
            "sessionId": session_row.id,
            "otp": otp,
            "bluetoothSessionId": session_row.bluetooth_session_id
        }


# End session
@app.post("/api/sessions/end")
def end_session(session_id: int = Body(...), current_user: User = Depends(get_current_user)):
    with Session(engine) as db:
        sess = db.get(AttendanceSession, session_id)
        if not sess:
            raise HTTPException(status_code=404, detail="Session not found")
        if sess.instructor_id != current_user.id:
            raise HTTPException(status_code=403, detail="Not allowed")
        sess.end_time = datetime.utcnow()
        db.add(sess)
        db.commit()
        return {"success": True}

# Student check-in
@app.post("/api/attendance/checkin")
def checkin(session_id: int = Body(...), otp: str = Body(...), current_user: User = Depends(get_current_user)):
    if current_user.role != "student":
        raise HTTPException(status_code=403, detail="Only students can check in")
    with Session(engine) as db:
        sess = db.get(AttendanceSession, session_id)
        if not sess:
            raise HTTPException(status_code=404, detail="Session not found")
        # Validate OTP
        if sess.otp != otp:
            raise HTTPException(status_code=400, detail="Invalid OTP")
        # Check if already checked in
        stmt = select(AttendanceLog).where(AttendanceLog.session_id == session_id, AttendanceLog.student_id == current_user.id)
        existing = db.exec(stmt).first()
        if existing:
            raise HTTPException(status_code=400, detail="Already checked in")
        log = AttendanceLog(session_id=session_id, student_id=current_user.id)
        db.add(log)
        db.commit()
        db.refresh(log)
        return {"success": True, "attendanceLogId": log.id, "checkInTime": log.check_in_time}

# Optional: student checkout
@app.post("/api/attendance/checkout")
def checkout(session_id: int = Body(...), current_user: User = Depends(get_current_user)):
    if current_user.role != "student":
        raise HTTPException(status_code=403, detail="Only students can check out")
    with Session(engine) as db:
        stmt = select(AttendanceLog).where(AttendanceLog.session_id == session_id, AttendanceLog.student_id == current_user.id)
        log = db.exec(stmt).first()
        if not log:
            raise HTTPException(status_code=404, detail="Attendance log not found")
        if log.check_out_time:
            raise HTTPException(status_code=400, detail="Already checked out")
        log.check_out_time = datetime.utcnow()
        # compute simple total_class_time in minutes if check_in exists
        if log.check_in_time:
            diff = log.check_out_time - log.check_in_time
            log.total_class_time = int(diff.total_seconds() // 60)
        db.add(log)
        db.commit()
        return {"success": True, "checkOutTime": log.check_out_time, "totalClassTimeMins": log.total_class_time}

# List attendance for a session (instructor)
@app.get("/api/sessions/{session_id}/attendance")
def session_attendance(session_id: int, current_user: User = Depends(get_current_user)):
    with Session(engine) as db:
        sess = db.get(AttendanceSession, session_id)
        if not sess:
            raise HTTPException(status_code=404, detail="Session not found")
        if current_user.role != "instructor" or sess.instructor_id != current_user.id:
            raise HTTPException(status_code=403, detail="Not allowed")
        stmt = select(AttendanceLog).where(AttendanceLog.session_id == session_id)
        logs = db.exec(stmt).all()
        return {"session": {"id": sess.id, "start_time": sess.start_time, "end_time": sess.end_time}, "attendance": logs}
