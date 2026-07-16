import datetime
from functools import wraps
import jwt
from flask import Blueprint, request, jsonify, current_app
from werkzeug.security import check_password_hash
from .models import db, Note, User

api_bp = Blueprint("api", __name__)


def make_token(user):
    # [HARDENING A08] token krotkozyjacy (1 h) z jawnym wydawca i odbiorca
    now = datetime.datetime.utcnow()
    payload = {
        "sub": str(user.id),
        "email": user.email,
        "iss": current_app.config["JWT_ISSUER"],
        "aud": current_app.config["JWT_AUDIENCE"],
        "iat": now,
        "exp": now + datetime.timedelta(hours=1),
    }
    return jwt.encode(payload, current_app.config["JWT_SECRET"], algorithm="HS256")


def jwt_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            current_app.logger.warning(
                "SECURITY event=jwt_validation_failure "
                "reason=missing_bearer ip=%s method=%s path=%s",
                request.remote_addr,
                request.method,
                request.path,
            )
            return jsonify(error="unauthorized"), 401
        try:
            # [HARDENING A08] pelna walidacja: podpis, exp, wydawca oraz odbiorca
            payload = jwt.decode(
                auth[7:], current_app.config["JWT_SECRET"], algorithms=["HS256"],
                audience=current_app.config["JWT_AUDIENCE"],
                issuer=current_app.config["JWT_ISSUER"],
            )
        except Exception as exc:
          current_app.logger.warning(
              "SECURITY event=jwt_validation_failure "
              "reason=%s ip=%s method=%s path=%s",
              type(exc).__name__,
              request.remote_addr,
              request.method,
              request.path,
          )

          return jsonify(error="unauthorized"), 401
        request.user_id = int(payload["sub"])
        return f(*args, **kwargs)
    return wrapper


@api_bp.route("/api/login", methods=["POST"])
def api_login():
    data = request.get_json(force=True, silent=True) or {}

    email = data.get("email", "")
    password = data.get("password", "")

    user = User.query.filter_by(email=email).first()

    if not user or not check_password_hash(
        user.password_hash,
        password,
    ):
        current_app.logger.warning(
            "SECURITY event=authentication_failure "
            "channel=api user=%s ip=%s "
            "method=%s path=%s reason=invalid_credentials",
            email,
            request.remote_addr,
            request.method,
            request.path,
        )

        return jsonify(error="unauthorized"), 401

    return jsonify(token=make_token(user))


@api_bp.route("/api/notes")
@jwt_required
def api_notes():
    notes = Note.query.filter_by(owner_id=request.user_id).all()
    return jsonify([{"id": n.id, "title": n.title, "body": n.body} for n in notes])


@api_bp.route("/api/notes/<int:note_id>")
@jwt_required
def api_note(note_id):
    n = db.get_or_404(Note, note_id)
    # [HARDENING A01] weryfikacja wlasciciela rowniez w warstwie API
    if n.owner_id != request.user_id:
         current_app.logger.warning(
             "SECURITY event=idor_denied "
             "channel=api user_id=%s note_id=%s "
             "owner_id=%s ip=%s method=%s path=%s",
             request.user_id,
             note_id,
             n.owner_id,
             request.remote_addr,
             request.method,
             request.path,
         )
        
         return jsonify(error="not found"), 404
    return jsonify({"id": n.id, "title": n.title, "body": n.body, "owner_id": n.owner_id})
