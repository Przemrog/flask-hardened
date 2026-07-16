import os
import uuid
import warnings

from flask import (
    Blueprint,
    abort,
    current_app,
    redirect,
    render_template,
    request,
    send_from_directory,
)
from flask_login import current_user, login_required
from PIL import Image, ImageOps, UnidentifiedImageError

from .models import Note, db

main_bp = Blueprint("main", __name__)

# [HARDENING A08] Akceptowane formaty są ustalane na podstawie
# rzeczywistej zawartości pliku, a nie rozszerzenia lub Content-Type.
ALLOWED_IMAGE_FORMATS = {"PNG", "JPEG"}
MAX_IMAGE_WIDTH = 4096
MAX_IMAGE_HEIGHT = 4096
MAX_IMAGE_PIXELS = 16_000_000


def _admin_required():
    # [HARDENING A01] eskalacja pionowa zamknieta - wymagana rola ADMIN
    if current_user.role != "ADMIN":
        current_app.logger.warning(
            "SECURITY event=authorization_denied "
            "user=%s user_id=%s role=%s ip=%s "
            "method=%s path=%s required_role=ADMIN",
            getattr(current_user, "email", "?"),
            current_user.get_id(),
            getattr(current_user, "role", "?"),
            request.remote_addr,
            request.method,
            request.path,
        )

        abort(403)


def _upload_folder() -> str:
    """Zwraca jeden, bezwzględny katalog używany do zapisu i odczytu awatarów."""
    return current_app.config["UPLOAD_FOLDER"]


def _save_normalized_avatar(file_storage) -> str:
    """Waliduje obraz na podstawie zawartości i zapisuje własny plik PNG.

    Oryginalne bajty użytkownika nie są publikowane. Obraz jest dwukrotnie
    otwierany: pierwsze otwarcie z ``verify`` sprawdza strukturę pliku,
    a drugie dekoduje piksele i pozwala znormalizować wynik.
    """
    try:
        file_storage.stream.seek(0)

        with warnings.catch_warnings():
            warnings.simplefilter("error", Image.DecompressionBombWarning)

            with Image.open(file_storage.stream) as probe:
                detected_format = (probe.format or "").upper()
                width, height = probe.size

                if detected_format not in ALLOWED_IMAGE_FORMATS:
                    abort(400, "Dozwolone sa wylacznie obrazy PNG i JPEG.")

                if (
                    width <= 0
                    or height <= 0
                    or width > MAX_IMAGE_WIDTH
                    or height > MAX_IMAGE_HEIGHT
                    or width * height > MAX_IMAGE_PIXELS
                ):
                    abort(400, "Wymiary obrazu sa nieprawidlowe lub zbyt duze.")

                probe.verify()

            file_storage.stream.seek(0)

            with Image.open(file_storage.stream) as source:
                source.load()
                normalized = ImageOps.exif_transpose(source)

                # PNG obsługuje przezroczystość; pozostałe tryby są
                # sprowadzane do deterministycznego rastra RGB/RGBA.
                output_mode = "RGBA" if "A" in normalized.getbands() else "RGB"
                normalized = normalized.convert(output_mode)

                safe_name = f"{uuid.uuid4().hex}.png"
                upload_dir = _upload_folder()
                os.makedirs(upload_dir, exist_ok=True)

                final_path = os.path.join(upload_dir, safe_name)
                temporary_path = final_path + ".tmp"

                try:
                    # [HARDENING A08] ponowne kodowanie usuwa zależność od
                    # nazwy, MIME i oryginalnej struktury przesłanego pliku.
                    normalized.save(temporary_path, format="PNG", optimize=True)
                    os.replace(temporary_path, final_path)
                finally:
                    if os.path.exists(temporary_path):
                        os.remove(temporary_path)

                return safe_name

    except (
        UnidentifiedImageError,
        OSError,
        ValueError,
        Image.DecompressionBombError,
        Image.DecompressionBombWarning,
    ):
        abort(400, "Plik nie jest prawidlowym obrazem PNG lub JPEG.")


@main_bp.route("/")
def home():
    return redirect("/notes")


@main_bp.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    user = current_user
    if request.method == "POST":
        avatar = request.files.get("avatar")
        if avatar and avatar.filename:
            safe_name = _save_normalized_avatar(avatar)
            user.avatar_path = "/avatars/" + safe_name
            db.session.commit()
        return redirect("/profile")
    return render_template("profile.html", user=user)


@main_bp.route("/avatars/<path:filename>")
def avatars(filename):
    # [HARDENING A08] katalog jest bezwzględny i identyczny z katalogiem
    # zapisu. Wcześniej zapis trafiał do /app/uploads, a względna ścieżka
    # send_from_directory była rozwiązywana względem app.root_path
    # (/app/app/uploads), co powodowało 404 i wynik INCONCLUSIVE.
    return send_from_directory(_upload_folder(), filename)


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
