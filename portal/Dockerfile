FROM node:22-alpine AS session-build
WORKDIR /session
COPY package.json package-lock.json ./
RUN npm ci --ignore-scripts --omit=dev

FROM python:3.13-alpine
WORKDIR /app
RUN apk add --no-cache nodejs
COPY requirements.lock .
RUN pip install --no-cache-dir --only-binary=:all: --require-hashes -r requirements.lock
COPY --from=session-build /session/node_modules ./node_modules
COPY session.mjs ./
COPY *.py ./
COPY static ./static
RUN mkdir -p /data /ru-configs && chown 65532:65532 /data /ru-configs && chmod 0770 /data && chmod 0700 /ru-configs
USER 65532:65532
EXPOSE 8080
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8080", "--proxy-headers"]
