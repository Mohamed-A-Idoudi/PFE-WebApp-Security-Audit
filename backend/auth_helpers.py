import jwt
from flask import request, jsonify, g, current_app
from functools import wraps
from datetime import datetime, timedelta, timezone


def generate_token(user) -> str:
    payload = {
        "user_id": user.id,
        "email":   user.email,
        "role":    user.role,
        "exp":     datetime.now(timezone.utc) + timedelta(hours=8),
    }
    return jwt.encode(payload, current_app.config["SECRET_KEY"], algorithm="HS256")


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            token = auth_header.split(" ")[1]
        if not token:
            return jsonify({"error": "Token missing"}), 401
        try:
            payload = jwt.decode(
                token,
                current_app.config["SECRET_KEY"],
                algorithms=["HS256"]
            )
            g.current_user_id = payload["user_id"]
            g.current_role    = payload["role"]
        except jwt.ExpiredSignatureError:
            return jsonify({"error": "Token expired"}), 401
        except jwt.InvalidTokenError:
            return jsonify({"error": "Invalid token"}), 401
        return f(*args, **kwargs)
    return decorated


def analyst_required(f):
    @wraps(f)
    @token_required
    def decorated(*args, **kwargs):
        if g.current_role not in ["analyst", "admin"]:
            return jsonify({"error": "Analyst access required"}), 403
        return f(*args, **kwargs)
    return decorated
