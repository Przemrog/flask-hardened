from app import create_app

app = create_app()

if __name__ == "__main__":
    # Uruchomienie produkcyjne realizuje gunicorn (patrz Dockerfile). Ten tryb tylko pomocniczo.
    app.run(host="0.0.0.0", port=8080, debug=False)
