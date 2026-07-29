# ArsGoatia Web — multi-stage build
# Context: apps/web/ (from docker-compose)

# ---------------------------------------------------------------------------
# Stage 1: build the React+Vite application
# ---------------------------------------------------------------------------
FROM node:20-alpine AS builder

WORKDIR /build

COPY package.json ./
RUN npm install --ignore-scripts

COPY index.html vite.config.ts tsconfig*.json ./
COPY src/ src/

RUN npm run build

# ---------------------------------------------------------------------------
# Stage 2: nginx runtime
# ---------------------------------------------------------------------------
FROM nginx:alpine

# Remove default config
RUN rm /etc/nginx/conf.d/default.conf

COPY nginx.conf /etc/nginx/conf.d/default.conf

# Copy built assets from the builder stage
COPY --from=builder /build/dist /usr/share/nginx/html

EXPOSE 80

HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=3 \
    CMD wget -qO- http://localhost:80/healthz || exit 1

CMD ["nginx", "-g", "daemon off;"]
