FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy poetry files (rutas corregidas)
COPY pyproject.toml poetry.lock ./

# Install poetry and dependencies
RUN pip install poetry && \
    poetry config virtualenvs.create false && \
    poetry install --only=main

# Copy application code
COPY phisherman-feeds/ ./phisherman-feeds/
COPY phisherman/ ./phisherman/

# Set Python path
ENV PYTHONPATH=/app

EXPOSE 8001

CMD ["uvicorn", "phisherman-feeds.main:app", "--host", "0.0.0.0", "--port", "8001"]
