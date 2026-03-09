FROM node:20-alpine

WORKDIR /app

# Install dependencies (cached layer)
COPY package.json package-lock.json ./
RUN npm ci

# Copy source
COPY . .

EXPOSE 5173

# Dev server with hot reload — vite proxy routes /m2m, /refinery, /health to api:8000
CMD ["npm", "run", "dev"]
