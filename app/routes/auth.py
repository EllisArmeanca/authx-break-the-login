from flask import Blueprint, render_template, request, redirect, url_for, session

from app.utils.db import get_db_connection
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import secrets

auth_bp = Blueprint("auth", __name__)


@auth_bp.route("/register", methods=["GET", "POST"])
def register():
    conn = get_db_connection()
    cursor = conn.cursor()

    # 🔐 verificăm dacă există deja manager (folosit și pentru HTML)
    existing_manager = cursor.execute(
        "SELECT id FROM users WHERE role = 'MANAGER'"
    ).fetchone()

    if request.method == "POST":
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "").strip()
        role = request.form.get("role", "ANALYST").strip()

        # 🔐 password policy
        if not is_strong_password(password):
            conn.close()
            write_audit_log(None, "REGISTER_WEAK_PASSWORD", "auth", email)
            return "Password does not meet security requirements", 400

        existing_user = cursor.execute(
            "SELECT id FROM users WHERE email = ?",
            (email,)
        ).fetchone()

        if existing_user:
            conn.close()
            write_audit_log(existing_user["id"], "REGISTER_DUPLICATE_EMAIL", "auth", email)
            return "Registration failed", 400

        # 🔐 blocare creare manager dacă există deja
        if role == "MANAGER" and existing_manager:
            conn.close()
            write_audit_log(None, "REGISTER_MANAGER_BLOCKED", "auth", email)
            return "Manager account already exists", 403

        password_hash = generate_password_hash(password)

        cursor.execute(
            """
            INSERT INTO users (email, password_hash, role, created_at)
            VALUES (?, ?, ?, ?)
            """,
            (email, password_hash, role, datetime.now().isoformat())
        )

        new_user_id = cursor.lastrowid

        conn.commit()
        conn.close()

        write_audit_log(new_user_id, "REGISTER_SUCCESS", "auth", str(new_user_id))

        return redirect(url_for("auth.login"))

    conn.close()
    return render_template("register.html", manager_exists=bool(existing_manager))

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

        now = datetime.now()

        #  user enumeration fix
        if not user:
            conn.close()
            write_audit_log(None, "LOGIN_FAILED_NO_USER", "auth", email)
            return "Invalid credentials", 401

        #  brute force lock check
        if user["locked_until"]:
            locked_until = datetime.fromisoformat(user["locked_until"])
            if now < locked_until:
                conn.close()
                write_audit_log(user["id"], "LOGIN_BLOCKED", "auth", str(user["id"]))
                return "Invalid credentials", 401

        #  password check
        if not check_password_hash(user["password_hash"], password):
            attempts = user["failed_login_attempts"] + 1

            lock_until = None
            if attempts >= 5:
                lock_until = (now + timedelta(minutes=5)).isoformat()
                attempts = 0

            cursor.execute(
                "UPDATE users SET failed_login_attempts = ?, locked_until = ? WHERE id = ?",
                (attempts, lock_until, user["id"])
            )

            conn.commit()
            conn.close()
            write_audit_log(user["id"], "LOGIN_FAILED_BAD_PASSWORD", "auth", str(user["id"]))

            return "Invalid credentials", 401

        #  reset attempts on success
        cursor.execute(
            "UPDATE users SET failed_login_attempts = 0, locked_until = NULL WHERE id = ?",
            (user["id"],)
        )

        session_token = secrets.token_urlsafe(32)

        cursor.execute(
            "UPDATE users SET failed_login_attempts = 0, locked_until = NULL, session_token = ? WHERE id = ?",
            (session_token, user["id"])
        )

        session.clear()
        session.permanent = True
        session["user_id"] = user["id"]
        session["user_email"] = user["email"]
        session["role"] = user["role"]
        session["session_token"] = session_token

            
        #session.clear() curata orice sesiune veche
        #session.permanent = true face sa se aplice expriarea de 15 minute din permanent_session_lifetime

        conn.commit()
        conn.close()
        write_audit_log(user["id"], "LOGIN_SUCCESS", "auth", str(user["id"]))

        return redirect(url_for("auth.dashboard"))

    return render_template("login.html")


@auth_bp.route("/dashboard")
def dashboard():
    if "user_id" not in session:
        return redirect(url_for("auth.login"))

    conn = get_db_connection()
    cursor = conn.cursor()

    user = cursor.execute(
        "SELECT session_token FROM users WHERE id = ?",
        (session["user_id"],)
    ).fetchone()

    if not user or not session.get("session_token") or session.get("session_token") != user["session_token"]:
        conn.close()
        session.clear()
        return redirect(url_for("auth.login"))

    user_id = session["user_id"]
    role = session.get("role")

    ticket_search = request.args.get("ticket_search", "").strip()
    user_search = request.args.get("user_search", "").strip()

    tickets = []
    users = []

    if role == "MANAGER":
        if ticket_search:
            tickets = cursor.execute(
                """
                SELECT tickets.*, users.email AS owner_email
                FROM tickets
                JOIN users ON tickets.owner_id = users.id
                WHERE tickets.title LIKE ? OR tickets.description LIKE ?
                ORDER BY tickets.created_at DESC
                """,
                (f"%{ticket_search}%", f"%{ticket_search}%")
            ).fetchall()

            write_audit_log(user_id, "SEARCH_TICKETS", "ticket", ticket_search)
        else:
            tickets = cursor.execute(
                """
                SELECT tickets.*, users.email AS owner_email
                FROM tickets
                JOIN users ON tickets.owner_id = users.id
                ORDER BY tickets.created_at DESC
                """
            ).fetchall()

        if user_search:
            users = cursor.execute(
                """
                SELECT id, email, role, created_at
                FROM users
                WHERE email LIKE ?
                ORDER BY created_at DESC
                """,
                (f"%{user_search}%",)
            ).fetchall()

            write_audit_log(user_id, "SEARCH_USERS", "auth", user_search)
        else:
            users = cursor.execute(
                """
                SELECT id, email, role, created_at
                FROM users
                ORDER BY created_at DESC
                """
            ).fetchall()

    else:
        if ticket_search:
            tickets = cursor.execute(
                """
                SELECT tickets.*, users.email AS owner_email
                FROM tickets
                JOIN users ON tickets.owner_id = users.id
                WHERE tickets.owner_id = ?
                  AND (tickets.title LIKE ? OR tickets.description LIKE ?)
                ORDER BY tickets.created_at DESC
                """,
                (user_id, f"%{ticket_search}%", f"%{ticket_search}%")
            ).fetchall()

            write_audit_log(user_id, "SEARCH_OWN_TICKETS", "ticket", ticket_search)
        else:
            tickets = cursor.execute(
                """
                SELECT tickets.*, users.email AS owner_email
                FROM tickets
                JOIN users ON tickets.owner_id = users.id
                WHERE tickets.owner_id = ?
                ORDER BY tickets.created_at DESC
                """,
                (user_id,)
            ).fetchall()

    conn.close()

    write_audit_log(user_id, "VIEW_DASHBOARD", "auth", str(user_id))

    return render_template(
        "dashboard.html",
        email=session.get("user_email"),
        role=session.get("role"),
        tickets=tickets,
        users=users,
        ticket_search=ticket_search,
        user_search=user_search
    )

def is_valid_session():
    if "user_id" not in session:
        return False

    conn = get_db_connection()
    cursor = conn.cursor()

    user = cursor.execute(
        "SELECT session_token FROM users WHERE id = ?",
        (session["user_id"],)
    ).fetchone()

    conn.close()

    if not user:
        return False

    if not session.get("session_token"):
        return False

    if session.get("session_token") != user["session_token"]:
        return False

    return True

@auth_bp.route("/tickets/create", methods=["GET", "POST"])
def create_ticket():
    if not is_valid_session():
        session.clear()
        return redirect(url_for("auth.login"))

    if not is_manager():
        write_audit_log(session["user_id"], "UNAUTHORIZED_TICKET_CREATE", "ticket")
        return "Forbidden", 403

    conn = get_db_connection()
    cursor = conn.cursor()

    analysts = cursor.execute(
        """
        SELECT id, email, role
        FROM users
        WHERE role IN ('ANALYST', 'MANAGER')
        ORDER BY email
        """
    ).fetchall()

    if request.method == "POST":
        title = request.form.get("title", "").strip()
        description = request.form.get("description", "").strip()
        severity = request.form.get("severity", "LOW").strip()
        status = request.form.get("status", "OPEN").strip()
        owner_id = request.form.get("owner_id", "").strip()

        if not title or not description or not owner_id:
            conn.close()
            return "All fields are required", 400

        owner = cursor.execute(
            "SELECT id, email, role FROM users WHERE id = ?",
            (owner_id,)
        ).fetchone()

        if not owner:
            conn.close()
            return "Invalid owner", 400

        cursor.execute(
            """
            INSERT INTO tickets (title, description, severity, status, owner_id, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                title,
                description,
                severity,
                status,
                owner["id"],
                datetime.now().isoformat(),
                datetime.now().isoformat()
            )
        )

        ticket_id = cursor.lastrowid

        conn.commit()
        conn.close()

        write_audit_log(session["user_id"], "CREATE_TICKET", "ticket", str(ticket_id), ticket_id)

        return redirect(url_for("auth.dashboard"))

    conn.close()
    return render_template("create_ticket.html", analysts=analysts)

@auth_bp.route("/tickets/<int:ticket_id>/edit", methods=["GET", "POST"])
def edit_ticket(ticket_id):
    if not is_valid_session():
        session.clear()
        return redirect(url_for("auth.login"))

    if not is_manager():
        write_audit_log(session["user_id"], "UNAUTHORIZED_TICKET_EDIT", "ticket", str(ticket_id), ticket_id)
        return "Forbidden", 403

    conn = get_db_connection()
    cursor = conn.cursor()

    ticket = cursor.execute(
        "SELECT * FROM tickets WHERE id = ?",
        (ticket_id,)
    ).fetchone()

    if not ticket:
        conn.close()
        return "Ticket not found", 404

    analysts = cursor.execute(
        """
        SELECT id, email, role
        FROM users
        WHERE role IN ('ANALYST', 'MANAGER')
        ORDER BY email
        """
    ).fetchall()

    if request.method == "POST":
        title = request.form.get("title", "").strip()
        description = request.form.get("description", "").strip()
        severity = request.form.get("severity", "LOW").strip()
        status = request.form.get("status", "OPEN").strip()
        owner_id = request.form.get("owner_id", "").strip()

        if not title or not description or not owner_id:
            conn.close()
            return "All fields are required", 400

        owner = cursor.execute(
            "SELECT id FROM users WHERE id = ?",
            (owner_id,)
        ).fetchone()

        if not owner:
            conn.close()
            return "Invalid owner", 400

        cursor.execute(
            """
            UPDATE tickets
            SET title = ?, description = ?, severity = ?, status = ?, owner_id = ?, updated_at = ?
            WHERE id = ?
            """,
            (
                title,
                description,
                severity,
                status,
                owner_id,
                datetime.now().isoformat(),
                ticket_id
            )
        )

        conn.commit()
        conn.close()

        write_audit_log(session["user_id"], "EDIT_TICKET", "ticket", str(ticket_id), ticket_id)

        return redirect(url_for("auth.view_ticket", ticket_id=ticket_id))

    conn.close()
    return render_template("edit_ticket.html", ticket=ticket, analysts=analysts)

@auth_bp.route("/tickets/<int:ticket_id>")
def view_ticket(ticket_id):
    if "user_id" not in session:
        return redirect(url_for("auth.login"))

    conn = get_db_connection()
    cursor = conn.cursor()

    user = cursor.execute(
        "SELECT session_token FROM users WHERE id = ?",
        (session["user_id"],)
    ).fetchone()

    if not user or not session.get("session_token") or session.get("session_token") != user["session_token"]:
        conn.close()
        session.clear()
        return redirect(url_for("auth.login"))

    ticket = cursor.execute(
        """
        SELECT tickets.*, users.email AS owner_email
        FROM tickets
        JOIN users ON tickets.owner_id = users.id
        WHERE tickets.id = ?
        """,
        (ticket_id,)
    ).fetchone()

    if not ticket:
        conn.close()
        return "Ticket not found", 404

    user_id = session["user_id"]
    role = session.get("role")

    if role != "MANAGER" and ticket["owner_id"] != user_id:
        conn.close()
        write_audit_log(user_id, "UNAUTHORIZED_TICKET_ACCESS", "ticket", str(ticket_id), ticket_id)
        return "Forbidden", 403

    conn.close()
    write_audit_log(user_id, "VIEW_TICKET", "ticket", str(ticket_id), ticket_id)

    return render_template("ticket_detail.html", ticket=ticket)

@auth_bp.route("/logout")
def logout():
    user_id = session.get("user_id")

    if user_id:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE users SET session_token = NULL WHERE id = ?",
            (user_id,)
        )
        conn.commit()
        conn.close()

        write_audit_log(user_id, "LOGOUT", "auth", str(user_id))

    session.clear()
    return redirect(url_for("auth.login"))

@auth_bp.route("/")
def index():
    return redirect(url_for("auth.login"))

@auth_bp.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        email = request.form.get("email", "").strip()

        conn = get_db_connection()
        cursor = conn.cursor()

        user = cursor.execute(
            "SELECT * FROM users WHERE email = ?",
            (email,)
        ).fetchone()

        # nu mai dai info daca exista sau nu
        if not user:
            conn.close()
            write_audit_log(None, "PASSWORD_RESET_REQUEST_UNKNOWN_EMAIL", "auth", email)
            return "If the account exists, a reset link was sent."

        raw_token = secrets.token_urlsafe(32)
        token_hash = generate_password_hash(raw_token)

        expires_at = (datetime.now() + timedelta(minutes=15)).isoformat()

        cursor.execute(
            """
            INSERT INTO password_reset_tokens (user_id, token_hash, expires_at, created_at)
            VALUES (?, ?, ?, ?)
            """,
            (user["id"], token_hash, expires_at, datetime.now().isoformat())
        )

        conn.commit()
        conn.close()

        write_audit_log(user["id"], "PASSWORD_RESET_REQUEST", "auth", str(user["id"]))

        print(f"[RESET LINK] http://127.0.0.1:5000/reset-password/{raw_token}")
        return "If the account exists, a reset link was sent."

    return render_template("forgot_password.html")


@auth_bp.route("/reset-password/<token>", methods=["GET", "POST"])
def reset_password(token):
    conn = get_db_connection()
    cursor = conn.cursor()

    tokens = cursor.execute(
        "SELECT * FROM password_reset_tokens WHERE used = 0"
    ).fetchall()

    valid_token = None

    for t in tokens:
        if check_password_hash(t["token_hash"], token):
            valid_token = t
            break

    if not valid_token:
        conn.close()
        write_audit_log(None, "PASSWORD_RESET_INVALID_TOKEN", "auth")

        return "Invalid or expired token", 400

    if datetime.now() > datetime.fromisoformat(valid_token["expires_at"]):
        cursor.execute(
            "UPDATE password_reset_tokens SET used = 1 WHERE id = ?",
            (valid_token["id"],)
        )
        conn.commit()
        conn.close()
        write_audit_log(valid_token["user_id"], "PASSWORD_RESET_EXPIRED_TOKEN", "auth", str(valid_token["user_id"]))

        return "Invalid or expired token", 400

    if request.method == "POST":
        new_password = request.form.get("password", "").strip()

        if not is_strong_password(new_password):
            conn.close()
            write_audit_log(valid_token["user_id"], "PASSWORD_RESET_WEAK_PASSWORD", "auth", str(valid_token["user_id"]))
            return "Password does not meet security requirements", 400

        new_hash = generate_password_hash(new_password)

        cursor.execute(
            "UPDATE users SET password_hash = ? WHERE id = ?",
            (new_hash, valid_token["user_id"])
        )

        cursor.execute(
            "UPDATE password_reset_tokens SET used = 1 WHERE id = ?",
            (valid_token["id"],)
        )

        conn.commit()
        conn.close()
        write_audit_log(valid_token["user_id"], "PASSWORD_RESET_SUCCESS", "auth", str(valid_token["user_id"]))

        return redirect(url_for("auth.login"))

    conn.close()
    return render_template("reset_password.html", token=token)


def is_strong_password(password):
    if len(password) < 8:
        return False
    if not any(c.islower() for c in password):
        return False
    if not any(c.isupper() for c in password):
        return False
    if not any(c.isdigit() for c in password):
        return False
    return True


def write_audit_log(user_id, action, resource, resource_id=None, ticket_id=None):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO audit_logs (user_id, ticket_id, action, resource, resource_id, timestamp, ip_address)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                user_id,
                ticket_id,
                action,
                resource,
                resource_id,
                datetime.now().isoformat(),
                request.remote_addr
            )
        )
        conn.commit()
        conn.close()
    except Exception:
        pass



def require_login():
    return "user_id" in session


def is_manager():
    return session.get("role") == "MANAGER"


def get_ticket_by_id(ticket_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    ticket = cursor.execute(
        """
        SELECT tickets.*, users.email AS owner_email
        FROM tickets
        JOIN users ON tickets.owner_id = users.id
        WHERE tickets.id = ?
        """,
        (ticket_id,)
    ).fetchone()
    conn.close()
    return ticket