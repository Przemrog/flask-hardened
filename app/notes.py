import ipaddress
import socket
import urllib.request
from urllib.parse import urlparse
from flask import Blueprint, request, render_template, redirect, abort
from flask_login import login_required, current_user
from .models import db, Note

notes_bp = Blueprint("notes", __name__)


def _owned_note(note_id):
    # [HARDENING A01] wspolna weryfikacja wlasciciela (deny-by-default)
    note = db.get_or_404(Note, note_id)
    if note.owner_id != current_user.id:
        abort(404)
    return note


@notes_bp.route("/notes")
@login_required
def index():
    notes = Note.query.filter_by(owner_id=current_user.id).all()
    return render_template("notes/index.html", notes=notes)


@notes_bp.route("/notes/<int:note_id>")
@login_required
def view(note_id):
    return render_template("notes/view.html", note=_owned_note(note_id))


@notes_bp.route("/notes/new")
@login_required
def create_form():
    return render_template("notes/create.html")


@notes_bp.route("/notes", methods=["POST"])
@login_required
def create():
    note = Note(owner_id=current_user.id, title=request.form["title"], body=request.form["body"])
    db.session.add(note)
    db.session.commit()
    return redirect("/notes")


@notes_bp.route("/notes/<int:note_id>/edit")
@login_required
def edit_form(note_id):
    return render_template("notes/edit.html", note=_owned_note(note_id))


@notes_bp.route("/notes/<int:note_id>/edit", methods=["POST"])
@login_required
def edit(note_id):
    note = _owned_note(note_id)
    note.title = request.form["title"]
    note.body = request.form["body"]
    db.session.commit()
    return redirect(f"/notes/{note_id}")


@notes_bp.route("/notes/<int:note_id>/delete", methods=["POST"])
@login_required
def delete(note_id):
    note = _owned_note(note_id)
    db.session.delete(note)
    db.session.commit()
    return redirect("/notes")


@notes_bp.route("/notes/search")
@login_required
def search():
    q = request.args.get("q", "")
    # [HARDENING A05] zapytanie ORM z parametryzowanym ILIKE (bez surowego SQL)
    notes = Note.query.filter(
        Note.owner_id == current_user.id,
        Note.title.ilike(f"%{q}%"),
    ).all()
    return render_template("notes/index.html", notes=notes, query=q)


def _ssrf_blocked(host):
    # [HARDENING A01/SSRF] blokada adresow prywatnych/loopback/link-local/reserved
    try:
        infos = socket.getaddrinfo(host, None)
    except Exception:
        return True
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast:
            return True
    return False


@notes_bp.route("/notes/import", methods=["POST"])
@login_required
def import_url():
    url = request.form["url"]
    parsed = urlparse(url)
    # [HARDENING A01/SSRF] dozwolone wylacznie http(s) + weryfikacja adresu docelowego
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        abort(400, "Niedozwolony URL.")
    if _ssrf_blocked(parsed.hostname):
        abort(400, "Zablokowano adres wewnetrzny (SSRF).")
    with urllib.request.urlopen(url, timeout=5) as resp:
        content = resp.read(1024 * 1024).decode("utf-8", errors="replace")
    note = Note(owner_id=current_user.id, title=f"Import z {parsed.hostname}", body=content)
    db.session.add(note)
    db.session.commit()
    return redirect("/notes")
