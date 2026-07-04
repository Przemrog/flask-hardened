# Wariant utwardzony Flask — wykaz zmian (do rozdziału 7 i PB3)

Lustrzana kopia aplikacji bazowej Flask z nałożonymi zabezpieczeniami. Każda zmiana zamyka
słabość oznaczoną w wariancie bazowym jako `[OWASP Axx]` i jest oznaczona jako `[HARDENING Axx]`.

## Mapa: słabość bazowa → utwardzenie

| OWASP 2025 | Wariant bazowy | Wariant utwardzony | Plik |
|---|---|---|---|
| A01 IDOR (poziomo) | pobranie po `id` bez sprawdzenia właściciela | `_owned_note` (deny-by-default) | `notes.py` |
| A01 IDOR (API)     | j.w. w warstwie API | weryfikacja właściciela w `api_note` | `api.py` |
| A01 eskalacja      | `/admin` dla każdego zalogowanego | `_admin_required` (rola ADMIN) | `main.py` |
| A01 SSRF           | `urllib.urlopen` na dowolnym URL | tylko http(s) + blokada adresów prywatnych/loopback | `notes.py` |
| A02 nagłówki       | brak | **Flask-Talisman**: CSP, HSTS, X-Frame-Options, nosniff, Referrer-Policy | `__init__.py` |
| A02/A10 błędy      | `debug=True` (traceback) | gunicorn (debug off) + globalny error handler | `Dockerfile`, `__init__.py` |
| A04 ciasteczka     | domyślne | HttpOnly + SameSite=Strict (+ Secure pod HTTPS) | `__init__.py` |
| A05 SQLi           | surowy SQL z f-stringiem | zapytanie ORM z parametryzowanym `ilike` | `notes.py` |
| A05 XSS            | filtr `\| safe` | `{{ note.body }}` (auto-escaping Jinja2) | `templates/notes/view.html` |
| A06/A07 rate limit | brak | **Flask-Limiter** na `/login` i `/api/login` | `auth.py`, `extensions.py` |
| A07 sesja          | ręczny `session['user_id']` | **Flask-Login** (ochrona przed fiksacją sesji) | `auth.py`, `models.py` |
| A07 polityka haseł | brak | min. 10 znaków, wielka litera, cyfra, znak specjalny | `auth.py` |
| A08 JWT            | brak walidacji issuer/audience, 24 h | walidacja issuer + audience, token 1 h | `api.py` |
| A08 upload         | oryginalna nazwa, brak walidacji | allowlist rozszerzeń, nazwa UUID, limit rozmiaru | `main.py`, `__init__.py` |
| A09 logowanie      | brak audytu | `app.logger.warning` przy nieudanym logowaniu | `auth.py` |
| A01/CSRF           | **brak jakiejkolwiek ochrony** | **Flask-WTF** (`CSRFProtect`) + tokeny w formularzach | `__init__.py`, `templates/*` |
| A03 zależności     | miejsce na pakiet z CVE | wersje wolne od podatności | `requirements.txt` |

## Nakład utwardzenia (dane do PB3 / H2) — kluczowy kontrast

To jest najmocniejszy materiał dla hipotezy H2. Zestawienie liczby **nowych zależności
zewnętrznych** dodanych wyłącznie w celu utwardzenia:

| Framework | Nowe zależności bezpieczeństwa | Uwaga |
|---|---|---|
| .NET      | **0** | rate limiting, anty-CSRF, nagłówki, HSTS, walidacja JWT — w rdzeniu |
| Spring    | **0** (ale własny kod na rate limiting) | CSRF/nagłówki w rdzeniu; limiter wymagał ~40 linii własnego kodu |
| **Flask** | **4** rozszerzenia | Flask-Login, Flask-WTF, flask-talisman, Flask-Limiter (+ gunicorn) |

Flask, jako mikroframework, wymagał dołożenia czterech osobnych rozszerzeń, aby osiągnąć poziom,
który .NET i Spring zapewniały w rdzeniu. To dokładnie mechanizm opisany w części teoretycznej
(filozofia „batteries-included" vs mikroframework) i najsilniejsza przesłanka empiryczna dla H2.

- **Pliki zmienione/dodane:** `__init__.py`, `models.py`, `auth.py`, `notes.py`, `main.py`,
  `api.py`, `requirements.txt`, `Dockerfile`, `docker-compose.yml`, wszystkie szablony formularzy
  oraz nowy `extensions.py`; usunięto `auth_utils.py` (zastąpiony przez Flask-Login).

> Dokładne liczby linii uzyskaj przez `diff -r flask-base flask-hardened` — najczystsze,
> powtarzalne źródło danych do tabeli nakładu.

## Uwaga o TLS
Aplikacja nasłuchuje po HTTP na :8080 (jak wariant bazowy), aby zachować identyczny sposób
testowania. `force_https` w Talismanie ustawiono na `False` (TLS terminuje reverse-proxy);
nagłówek HSTS i pozostałe zabezpieczenia działają niezależnie i są w pełni weryfikowalne po HTTP.
Flaga `Secure` ciasteczka aktywuje się pod HTTPS (zmienna `COOKIE_SECURE=1`).
