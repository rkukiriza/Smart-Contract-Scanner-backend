FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y \
    git \
    curl \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

RUN curl -L https://github.com/ethereum/solidity/releases/download/v0.8.20/solc-static-linux -o /usr/local/bin/solc \
    && chmod +x /usr/local/bin/solc

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN mkdir -p temp_contracts scan_results

EXPOSE $PORT

CMD uvicorn api:app --host 0.0.0.0 --port $PORT
