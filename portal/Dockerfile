FROM python:3.13-alpine
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app.py sync.py ./
COPY static ./static
RUN mkdir -p /data && chown 65532:65532 /data && chmod 0775 /data
USER 65532:65532
EXPOSE 8080
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8080", "--proxy-headers"]
