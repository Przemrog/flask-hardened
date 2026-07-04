import re
from flask import Blueprint, request, render_template, redirect, current_app
from flask_login import login_user, logout_user
from werkzeug.security import generate_password_hash, check_password_hash
from .models import db, User
from .extensions import limiter

auth_bp = Blueprint("auth", __name__)

# [HARDENING A07] polityka hasel: min. 10 znakow, wielka litera, cyfra, znak specjalny
PASSWORD_POLICY = re.compile(r"^(?=.*[A-Z])(?=.*[0-9])(?=.*[^A-Za-z0-9]).{10,}$")


@auth_bp.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]
        if User.query.filter_by(email=email).first():
            return render_template("register.html", error="Konto o tym adresie juz istnieje.")
        if not PASSWORD_POLICY.match(password):
            return render_template("register.html",
                                   error="Haslo: min. 10 znakow, wielka litera, cyfra i znak specjalny.")
        u = User(email=email, password_hash=generate_password_hash(password), role="USER")
        db.session.add(u)
        db.session.commit()
        login_user(u)
        return redirect("/notes")
    return render_template("register.html")


@auth_bp.route("/login", methods=["GET", "POST"])
@limiter.limit("5 per 30 seconds", methods=["POST"])  # [HARDENING A06/A07] limit prob logowania
def login():
    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]
        u = User.query.filter_by(email=email).first()
        if u and check_password_hash(u.password_hash, password):
            login_user(u)  # [HARDENING A07] sesja zarzadzana przez Flask-Login (ochrona przed fiksacja)
            return redirect("/notes")
        # [HARDENING A09] audyt nieudanej proby logowania
        current_app.logger.warning("Nieudane logowanie dla: %s", email)
        return render_template("login.html", error="Nieprawidlowy email lub haslo.")
    return render_template("login.html")


@auth_bp.route("/logout", methods=["POST"])
def logout():
    logout_user()
    return redirect("/login")
