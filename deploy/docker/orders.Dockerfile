FROM python:3.11-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PYTHONPATH=/app
WORKDIR /app
COPY requirements-app.txt .
RUN pip install --no-cache-dir -r requirements-app.txt
COPY services /app/services
USER 10001:10001
EXPOSE 8000
CMD ["uvicorn", "services.orders.app:app", "--host", "0.0.0.0", "--port", "8000"]
