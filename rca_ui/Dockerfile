FROM node:18-alpine
RUN apk add --no-cache certbot openssl
WORKDIR /app
COPY server.js .
COPY mock_data.json .
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
EXPOSE 8080 8443
ENTRYPOINT ["/entrypoint.sh"]
