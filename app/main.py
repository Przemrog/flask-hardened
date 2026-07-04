import os
import uuid
from flask import Blueprint, request, render_template, redirect, send_from_directory, abort
from flask_login import login_required, current_user
from werkzeug.utils import secure_filename
from .models import db, Note

main_bp = Blueprint("main", __name__)

ALLOWED_EXT = {"jpg", "jpeg", "png", "gif"}


def _admin_required():
    # [HARDENING A01] eskalacja pionowa zamknieta - wymagana rola ADMIN
    if current_user.role != "ADMIN":
        abort(403)


@main_bp.route("/")
def home():
    return redirect("/notes")


@main_bp.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    user = current_user
    if request.method == "POST":
        f = request.files.get("avatar")
        if f and f.filename:
            # [HARDENING A02/A08] walidacja rozszerzenia + bezpieczna, losowa nazwa pliku
            ext = f.filename.rsplit(".", 1)[-1].lower() if "." in f.filename else ""
            if ext not in ALLOWED_EXT:
                abort(400, "Niedozwolony typ pliku.")
            os.makedirs("uploads", exist_ok=True)
            safe_name = f"{uuid.uuid4().hex}.{ext}"
            f.save(os.path.join("uploads", secure_filename(safe_name)))
            user.avatar_path = "/avatars/" + safe_name
            db.session.commit()
        return redirect("/profile")
    return render_template("profile.html", user=user)


@main_bp.route("/avatars/<path:filename>")
def avatars(filename):
    return send_from_directory("uploads", filename)


@main_bp.route("/admin")
@login_required
def admin():
    _admin_required()
    notes = Note.query.all()
    return render_template("admin.html", notes=notes)


@main_bp.route("/debug/error")
@login_required
def debug_error():
    # [HARDENING A02/A10] przy debug=False i globalnym handlerze wyjatek nie ujawnia traceback
    value = int(request.args.get("input"))
    return f"Parsed: {value}"
