from flask import Blueprint, request, jsonify, g
from extensions import db, check_password
from auth_helpers import generate_token, token_required
from models import User

auth_bp = Blueprint("auth", __name__, url_prefix="/api/auth")


@auth_bp.route("/login", methods=["POST"])
def login():
    data     = request.get_json()
    email    = data.get("email", "").strip().lower()
    password = data.get("password", "")

    if not email or not password:
        return jsonify({"error": "Email and password required"}), 400

    user = db.session.execute(
        db.select(User).filter_by(email=email, is_active=True)
    ).scalar_one_or_none()

    if not user or not check_password(password, user.password_hash):
        return jsonify({"error": "Invalid credentials"}), 401

    token = generate_token(user)
    return jsonify({
        "token": token,
        "user":  {"id": user.id, "email": user.email, "role": user.role},
    })


@auth_bp.route("/me", methods=["GET"])
@token_required
def get_me():
    user = db.session.get(User, g.current_user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404
    return jsonify({"id": user.id, "email": user.email, "role": user.role})
