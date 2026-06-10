"""
WebCure — Authentication Blueprint
Provides user registration, login, logout, and current-user endpoints.
"""

from flask import Blueprint, request, jsonify
from flask_login import login_user, logout_user, login_required, current_user

from models import db, User

auth_bp = Blueprint("auth", __name__, url_prefix="/auth")


# ── POST /auth/register ───────────────────────────────────────────────────────

@auth_bp.route("/register", methods=["POST"])
def register():
    """Create a new user account."""
    body     = request.get_json(force=True, silent=True) or {}
    username = (body.get("username") or "").strip()
    email    = (body.get("email") or "").strip().lower()
    password = body.get("password") or ""

    # Basic validation
    if not username or not email or not password:
        return jsonify({"error": True, "message": "username, email, and password are required."}), 400

    if len(username) < 3 or len(username) > 64:
        return jsonify({"error": True, "message": "username must be between 3 and 64 characters."}), 400

    if len(password) < 8:
        return jsonify({"error": True, "message": "password must be at least 8 characters."}), 400

    if "@" not in email:
        return jsonify({"error": True, "message": "A valid email address is required."}), 400

    # Uniqueness checks
    if User.query.filter_by(username=username).first():
        return jsonify({"error": True, "message": "Username is already taken."}), 409

    if User.query.filter_by(email=email).first():
        return jsonify({"error": True, "message": "An account with that email already exists."}), 409

    user = User(username=username, email=email)
    user.set_password(password)
    db.session.add(user)
    db.session.commit()

    login_user(user)
    return jsonify({"message": "Account created successfully.", "user": user.to_dict()}), 201


# ── POST /auth/login ──────────────────────────────────────────────────────────

@auth_bp.route("/login", methods=["POST"])
def login():
    """Authenticate an existing user and start a session."""
    body     = request.get_json(force=True, silent=True) or {}
    username = (body.get("username") or "").strip()
    password = body.get("password") or ""

    if not username or not password:
        return jsonify({"error": True, "message": "username and password are required."}), 400

    user = User.query.filter_by(username=username).first()
    if user is None or not user.check_password(password):
        return jsonify({"error": True, "message": "Invalid username or password."}), 401

    login_user(user)
    return jsonify({"message": "Logged in successfully.", "user": user.to_dict()}), 200


# ── POST /auth/logout ─────────────────────────────────────────────────────────

@auth_bp.route("/logout", methods=["POST"])
@login_required
def logout():
    """End the current user's session."""
    logout_user()
    return jsonify({"message": "Logged out successfully."}), 200


# ── GET /auth/me ──────────────────────────────────────────────────────────────

@auth_bp.route("/me", methods=["GET"])
@login_required
def me():
    """Return the currently authenticated user's profile."""
    return jsonify({"user": current_user.to_dict()}), 200
