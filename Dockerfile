FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
EXPOSE 8080
# [HARDENING A02/A10] serwer produkcyjny (gunicorn), bez trybu debug -> brak wycieku traceback
CMD ["gunicorn", "-b", "0.0.0.0:8080", "-w", "2", "run:app"]
