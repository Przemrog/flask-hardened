# Aplikacja referencyjna — Flask, WARIANT UTWARDZONY

Lustrzana kopia aplikacji bazowej Flask z nałożonymi zabezpieczeniami. Ta sama funkcjonalność,
te same endpointy i baza. Pełne zestawienie zmian i dane do PB3 znajdują się w `HARDENING.md`.

## Uruchomienie
```bash
docker compose down -v
docker compose up --build
```
Aplikacja: http://localhost:8080 (gunicorn). Konta: admin@local/admin123, alice@local/alice123,
bob@local/bob123 — logowanie tymi kontami działa; polityka haseł dotyczy nowych rejestracji.

## Szybka weryfikacja skuteczności utwardzenia
- IDOR: `alice` otwiera `/notes/3` (notatka Boba) => 404.
- Eskalacja: `alice` wchodzi na `/admin` => 403.
- XSS: notatka z `<script>` => treść wyświetla się jako tekst.
- SQLi: `/notes/search?q=%' OR '1'='1` => brak wycieku (ORM, parametryzacja).
- SSRF: `/notes/import` z `http://169.254.169.254/...` lub `file:///etc/passwd` => 400.
- A10: `/debug/error?input=abc` => ogólny komunikat, bez traceback.
- Nagłówki: odpowiedź zawiera Content-Security-Policy, X-Frame-Options, X-Content-Type-Options.
- CSRF: POST bez tokenu `csrf_token` => 400.
- Rate limit: >5 prób logowania w 30 s => HTTP 429.

## Uwaga
Wariant utwardzony służy jako punkt odniesienia w porównaniu i jest przeznaczony wyłącznie
do kontrolowanych testów w izolowanym środowisku pracy magisterskiej.
