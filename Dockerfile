FROM node:23-alpine
WORKDIR /app

COPY package*.json ./
RUN set -eux; \
  if [ -f package-lock.json ]; then \
    npm ci --omit=dev --no-audit --no-fund; \
  else \
    npm install --omit=dev --no-audit --no-fund; \
  fi

COPY . .
EXPOSE 8080
CMD ["node", "server.js"]

