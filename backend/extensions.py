from flask_sqlalchemy import SQLAlchemy
import bcrypt as _bcrypt

db = SQLAlchemy()
def hash_password(password: str) -> str:
    return _bcrypt.hashpw(password.encode(), _bcrypt.gensalt()).decode()
def check_password(password: str, hashed: str) -> bool:
    return _bcrypt.checkpw(password.encode(), hashed.encode())
