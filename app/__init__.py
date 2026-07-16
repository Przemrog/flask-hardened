import os
import time
from flask import Flask, request
from werkzeug.exceptions import HTTPException
from flask_talisman import Talisman
from .models import db, seed_data, User
from .extensions import login_manager, csrf, limiter


def create_app():
    app = Flask(__name__)
    app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-insecure-flask-secret")
    app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get(
        "DATABASE_URL", "postgresql+psycopg2://notes:notes@localhost:5432/notesdb")
    app.config["JWT_SECRET"] = os.environ.get("JWT_SECRET", "dev-only-insecure-signing-key")
    app.config["JWT_ISSUER"] = os.environ.get("JWT_ISSUER", "notes-app")
    app.config["JWT_AUDIENCE"] = os.environ.get("JWT_AUDIENCE", "notes-app-clients")

    # [HARDENING A04] flagi ciasteczka sesyjnego
    app.config["SESSION_COOKIE_HTTPONLY"] = True
    app.config["SESSION_COOKIE_SAMESITE"] = "Strict"
    app.config["SESSION_COOKIE_SECURE"] = os.environ.get("COOKIE_SECURE", "0") == "1"
    app.config["MAX_CONTENT_LENGTH"] = 2 * 1024 * 1024  # [HARDENING A08] limit rozmiaru zadania

    # [HARDENING A08] pliki uruchomieniowe trafiają do katalogu instance,
    # oddzielonego od kodu aplikacji. Ścieżka bezwzględna jest używana
    # zarówno podczas zapisu, jak i serwowania plików.
    app.config["UPLOAD_FOLDER"] = os.path.join(app.instance_path, "uploads")
    os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)

    db.init_app(app)
    login_manager.init_app(app)
    login_manager.login_view = "auth.login"
    csrf.init_app(app)          # [HARDENING A01/CSRF] globalna ochrona anty-CSRF
    limiter.init_app(app)       # [HARDENING A06/A07] rate limiting

    # [HARDENING A02] naglowki bezpieczenstwa (CSP, HSTS, X-Frame-Options, nosniff, Referrer-Policy)
    Talisman(
        app,
        force_https=False,  # TLS terminuje reverse-proxy; naglowki dzialaja niezaleznie
        frame_options="DENY",
        strict_transport_security=True,
        referrer_policy="no-referrer",
        content_security_policy={
            "default-src": "'self'",
            "frame-ancestors": "'none'",
            "object-src": "'none'",
        },
    )

    @login_manager.user_loader
    def load_user(user_id):
        return db.session.get(User, int(user_id))

    from .auth import auth_bp
    from .notes import notes_bp
    from .main import main_bp
    from .api import api_bp
    app.register_blueprint(auth_bp)
    app.register_blueprint(notes_bp)
    app.register_blueprint(main_bp)
    app.register_blueprint(api_bp)

    # API dziala na tokenie Bearer, nie na ciasteczku -> wylaczenie CSRF dla warstwy /api
    csrf.exempt(api_bp)

    # [HARDENING A09]
    # Jawny audyt uruchomienia ograniczenia liczby żądań.
    @app.errorhandler(429)
    def handle_rate_limit(error):
        app.logger.warning(
            "SECURITY event=rate_limit_exceeded "
            "ip=%s method=%s path=%s",
            request.remote_addr,
            request.method,
            request.path,
        )

        return "Zbyt wiele prób. Spróbuj ponownie później.", 429

    # [HARDENING A02/A10] globalna obsluga bledow - komunikat ogolny, bez traceback
    @app.errorhandler(Exception)
    def handle_error(error):
        # Obsługiwane błędy HTTP, np. 400, 403 i 404,
        # nie wymagają pełnego tracebacka.
        if isinstance(error, HTTPException):
            if error.code == 404:
                return "Nie znaleziono.", 404
    
            return (
                error.description
                or "Żądanie zostało odrzucone.",
                error.code,
            )
    
        # [HARDENING A09/A10]
        # Pełny wyjątek trafia wyłącznie do logu serwera.
        app.logger.exception(
            "APPLICATION event=unhandled_exception "
            "ip=%s method=%s path=%s",
            request.remote_addr,
            request.method,
            request.path,
        )
    
        return (
            "Wystąpił nieoczekiwany błąd. "
            "Zdarzenie zostało zarejestrowane.",
            500,
        )

    with app.app_context():
        for attempt in range(10):
            try:
                db.create_all()
                seed_data()
                break
            except Exception:
                if attempt == 9:
                    raise
                time.sleep(3)

    return app
