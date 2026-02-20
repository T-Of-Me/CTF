FROM php:8.1-fpm-alpine

# Install nginx
RUN apk add --no-cache nginx

# Copy files
COPY config/nginx.conf /etc/nginx/nginx.conf
COPY src/index.php /var/www/html/
COPY service/docker-entrypoint.sh /entrypoint.sh

# Make entrypoint executable
RUN chmod +x /entrypoint.sh

# Create directories
RUN mkdir -p /var/log/nginx /run/nginx /var/www/html

# Set permissions
RUN chown -R www-data:www-data /var/www/html

EXPOSE 80

ENTRYPOINT ["/entrypoint.sh"]