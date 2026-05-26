import os
import bcrypt
from flask import Flask, jsonify
from flask_cors import CORS
from dotenv import load_dotenv
from extensions import db, hash_password

load_dotenv()


def create_app() -> Flask:
    app = Flask(__name__)

    # ── Config ────────────────────────────────────────────────────────────────
    app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv(
        "DATABASE_URL",
        "postgresql://securiscan:password@db:5432/securiscan"
    )
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    app.config["SECRET_KEY"] = os.getenv("SECRET_KEY")
    if not app.config["SECRET_KEY"]:
        raise RuntimeError("SECRET_KEY is not set in .env")

    # ── Extensions ────────────────────────────────────────────────────────────
    CORS(app,
         origins=["http://localhost:5173", "http://localhost:80", "http://localhost"],
         supports_credentials=True)
    db.init_app(app)

    # ── Blueprints ────────────────────────────────────────────────────────────
    from API_Calls.auth    import auth_bp
    from API_Calls.scans   import scans_bp
    from API_Calls.reports import reports_bp
    from API_Calls.users   import users_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(scans_bp)
    app.register_blueprint(reports_bp)
    app.register_blueprint(users_bp)

    # ── Health ────────────────────────────────────────────────────────────────
    @app.route("/api/health", methods=["GET"])
    def health():
        return jsonify({"status": "ok", "service": "SecuriScan API"})

    # ── Startup DB init ───────────────────────────────────────────────────────
    with app.app_context():
        from models import User
        db.create_all()

        # Fix ghost scans from previous crash
        db.session.execute(
            db.text("UPDATE scans SET status='error' WHERE status='running'")
        )
        db.session.commit()

        # Seed default users if first run
        exists = db.session.execute(
            db.select(User).filter_by(email="admin@securiscan.local")
        ).scalar_one_or_none()

        if not exists:
            db.session.add_all([
                User(
                    email="admin@securiscan.local",
                    password_hash=hash_password("admin123"),
                    role="admin"
                ),
                User(
                    email="analyst@securiscan.local",
                    password_hash=hash_password("analyst123"),
                    role="analyst"
                ),
            ])
            db.session.commit()
            print("[STARTUP] Default users created")

    return app


app = create_app()

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
