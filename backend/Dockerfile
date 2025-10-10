FROM python:3.12-alpine

WORKDIR /app

# Install system dependencies for psycopg2
RUN apk add --no-cache \
    postgresql-dev \
    gcc \
    musl-dev

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 5000

CMD ["python", "app.py"]
