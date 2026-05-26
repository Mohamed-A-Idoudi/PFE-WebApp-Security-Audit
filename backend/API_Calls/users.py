from flask import Blueprint, request, jsonify, g
from extensions import db, hash_password
from auth_helpers import token_required
from models import User

users_bp = Blueprint("users", __name__, url_prefix="/api")


@users_bp.route("/users", methods=["GET"])
@token_required
def list_users():
    if g.current_role != "admin":
        return jsonify({"error": "Admin access required"}), 403
    users = db.session.execute(db.select(User)).scalars().all()
    return jsonify([{
        "id":         u.id,
        "email":      u.email,
        "role":       u.role,
        "is_active":  u.is_active,
        "created_at": u.created_at.isoformat(),
    } for u in users])


@users_bp.route("/users", methods=["POST"])
@token_required
def create_user():
    if g.current_role != "admin":
        return jsonify({"error": "Admin access required"}), 403

    data     = request.get_json()
    email    = data.get("email", "").strip().lower()
    password = data.get("password", "")
    role     = data.get("role", "analyst")

    if not email or not password:
        return jsonify({"error": "Email and password required"}), 400

    existing = db.session.execute(
        db.select(User).filter_by(email=email)
    ).scalar_one_or_none()
    if existing:
        return jsonify({"error": "Email already exists"}), 409

    user = User(email=email, password_hash=hash_password(password), role=role)
    db.session.add(user)
    db.session.commit()
    return jsonify({"id": user.id, "email": user.email, "role": user.role}), 201


@users_bp.route("/users/<int:user_id>", methods=["PATCH"])
@token_required
def update_user(user_id):
    if g.current_role != "admin":
        return jsonify({"error": "Admin access required"}), 403

    user = db.session.get(User, user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404

    data = request.get_json()
    if "is_active" in data:
        user.is_active = data["is_active"]
    if "role" in data and data["role"] in ["admin", "analyst"]:
        user.role = data["role"]
    if "password" in data and data["password"]:
        user.password_hash = hash_password(data["password"])

    db.session.commit()
    return jsonify({"id": user.id, "email": user.email,
                    "role": user.role, "is_active": user.is_active})
