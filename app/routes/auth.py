from datetime import datetime

from flask import Blueprint, render_template, request, redirect, url_for, session

from app.utils.db import get_db_connection

auth_bp = Blueprint("auth", __name__)


@auth_bp.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "").strip()
        role = request.form.get("role", "ANALYST").strip()

        conn = get_db_connection()
        cursor = conn.cursor()

        existing_user = cursor.execute(
            "SELECT id FROM users WHERE email = ?",
            (email,)
        ).fetchone()

        if existing_user:
            conn.close()
            return "User already exists", 400

        cursor.execute(
            """
            INSERT INTO users (email, password, role, created_at, locked)
            VALUES (?, ?, ?, ?, ?)
            """,
            (email, password, role, datetime.now().isoformat(), 0)
        )

        conn.commit()
        conn.close()

        return redirect(url_for("auth.login"))

    return render_template("register.html")


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "").strip()

        conn = get_db_connection()
        cursor = conn.cursor()

        user = cursor.execute(
            "SELECT * FROM users WHERE email = ?",
            (email,)
        ).fetchone()

        if not user:
            conn.close()
            return "User does not exist", 404

        if user["locked"] == 1:
            conn.close()
            return "Account is locked", 403

        if user["password"] != password:
            conn.close()
            return "Wrong password", 401

        session["user_id"] = user["id"]
        session["user_email"] = user["email"]
        session["role"] = user["role"]

        conn.close()
        return redirect(url_for("auth.dashboard"))

    return render_template("login.html")


@auth_bp.route("/dashboard")
def dashboard():
    if "user_id" not in session:
        return redirect(url_for("auth.login"))

    return render_template(
        "dashboard.html",
        email=session.get("user_email"),
        role=session.get("role")
    )


@auth_bp.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("auth.login"))

@auth_bp.route("/")
def index():
    return redirect(url_for("auth.login"))