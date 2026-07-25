# ArsGoatia web UI.
# M0 scaffold: nginx serving a static placeholder and proxying /api -> api:8000.
# M2 replaces the static assets with a built React + Vite bundle (multi-stage
# node build) while keeping this nginx serving stage.
FROM nginx:alpine
COPY apps/web/nginx.conf /etc/nginx/conf.d/default.conf
COPY apps/web/public /usr/share/nginx/html
EXPOSE 80
