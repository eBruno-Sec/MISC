# KlyneDarius Construction Corporation — static marketing site
# Single-stage build: nginx serves the pre-built static files directly.
FROM nginx:1.27-alpine

# Remove default nginx site config and assets
RUN rm -rf /usr/share/nginx/html/* /etc/nginx/conf.d/default.conf

# Custom server config (gzip, cache headers, clean URLs, 404 handling)
COPY nginx.conf /etc/nginx/conf.d/default.conf

# Site files
COPY index.html about.html services.html permit-process.html projects.html quote.html contact.html 404.html /usr/share/nginx/html/
COPY assets/ /usr/share/nginx/html/assets/

EXPOSE 80

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s \
  CMD wget -qO- http://localhost/ > /dev/null || exit 1

CMD ["nginx", "-g", "daemon off;"]
