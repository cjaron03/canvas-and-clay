# Multi-stage build for optimized frontend image
# Stage 1: Builder - Install dependencies and build
FROM node:20-alpine AS builder

WORKDIR /usr/src/app

# Copy package files
COPY package*.json ./

# Install dependencies with BuildKit cache mount
RUN --mount=type=cache,target=/root/.npm \
    npm ci --prefer-offline --no-audit

# Copy source code
COPY . .

# Set default API base URL for build time
ARG PUBLIC_API_BASE_URL=http://localhost:5001
ENV PUBLIC_API_BASE_URL=$PUBLIC_API_BASE_URL

# Build the application
RUN npm run build

# Stage 2: Runtime - Minimal production preview server
FROM node:20-alpine

WORKDIR /usr/src/app

# Set production environment
ENV NODE_ENV=production

# Copy package files for reference
COPY package*.json ./

# Copy node_modules from builder (includes all dependencies)
# This avoids reinstalling and is faster
COPY --from=builder /usr/src/app/node_modules ./node_modules

# Copy built application from builder
COPY --from=builder /usr/src/app/.svelte-kit ./.svelte-kit

# Copy necessary source files for preview server
COPY svelte.config.js vite.config.js ./
COPY src ./src
# Note: static directory not needed for preview server

# Set the API base URL for runtime
ARG PUBLIC_API_BASE_URL=http://localhost:5001
ENV PUBLIC_API_BASE_URL=$PUBLIC_API_BASE_URL

EXPOSE 5173

# Run preview server
CMD ["npm", "run", "preview", "--", "--host", "0.0.0.0", "--port", "5173"]
