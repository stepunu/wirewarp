# Stage 1: Build React frontend
FROM node:22-alpine AS frontend
WORKDIR /web
COPY wirewarp-web/package.json wirewarp-web/package-lock.json ./
RUN npm ci
COPY wirewarp-web/ .
ENV BUILD_OUT=/out
RUN npm run build

# Stage 2: Python API server
FROM python:3.11-slim
WORKDIR /app

COPY wirewarp-server/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY wirewarp-server/ .
COPY --from=frontend /out ./static

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
