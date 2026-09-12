FROM python:3.13-alpine
WORKDIR /app
COPY portal/requirements.lock .
RUN pip install --no-cache-dir --only-binary=:all: --require-hashes -r requirements.lock
COPY portal/*.py ./
COPY awg/model.py ./awg/model.py
COPY portal/static ./static
COPY portal/templates ./templates
RUN mkdir -p /data /ru-configs /auth && chown 65532:65532 /data /ru-configs /auth && \
    chmod 0770 /data && chmod 0700 /ru-configs /auth
USER 65532:65532
EXPOSE 8080
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8080", "--proxy-headers", "--no-access-log"]
