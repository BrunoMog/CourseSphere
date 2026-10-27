# syntax=docker/dockerfile:1
# ---------------------------------------------------------
# Stage 1: Build Frontend Assets
# ---------------------------------------------------------
FROM node:20-alpine AS builder

WORKDIR /app

# Copy dependency manifests
COPY package*.json ./

# Install dependencies (ignoring optional post-install scripts for security)
RUN npm install

# Copy source code and build Vite static bundle
COPY . .
RUN npm run build

# ---------------------------------------------------------
# Stage 2: Production Nginx Static Server
# ---------------------------------------------------------
FROM nginx:alpine-slim

# Copy custom Nginx SPA configuration
COPY nginx.conf /etc/nginx/conf.d/default.conf

# Copy compiled static assets from builder stage
COPY --from=builder /app/dist /usr/share/nginx/html

EXPOSE 80

HEALTHCHECK --interval=30s --timeout=3s --retries=3 \
    CMD wget -q --spider http://localhost/ || exit 1

CMD ["nginx", "-g", "daemon off;"]
