import os
from datetime import timedelta
from flask import Flask

from app.routes.auth import auth_bp


def create_app():
    app = Flask(__name__)
    app.secret_key = os.environ.get("SECRET_KEY", "dev-only-change-me")

    app.config["SESSION_COOKIE_HTTPONLY"] = True ## cookiuul nu poate fi accesat din javascript; protejeaza de xss - furt de sesiune
    app.config["SESSION_COOKIE_SAMESITE"] = "Lax" # limiteaza trimiterea cookie-ului in requesturi cross-site
    app.config["SESSION_COOKIE_SECURE"] = False  # local lab only; True in production
    app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(minutes=15) # sesiuena xpira automat dupa 15 minute

    app.register_blueprint(auth_bp)

    return app
