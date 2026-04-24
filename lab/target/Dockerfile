FROM nginx:alpine
RUN apk add --no-cache iproute2
COPY entrypoint.sh /entrypoint.sh
COPY html /usr/share/nginx/html
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
