FROM nginx:latest

RUN mkdir -p /etc/nginx/ssl

COPY nginx.conf /etc/nginx/nginx.conf
COPY weak.crt /etc/nginx/ssl/weak.crt
COPY weak.key /etc/nginx/ssl/weak.key

EXPOSE 443
