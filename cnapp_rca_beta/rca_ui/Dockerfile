FROM node:18-alpine
RUN apk add --no-cache certbot openssl chromium
WORKDIR /app
COPY server.js .
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
EXPOSE 80 8443
ENTRYPOINT ["/entrypoint.sh"]
