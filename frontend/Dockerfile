FROM node:20-alpine

WORKDIR /usr/src/app

COPY package*.json ./
RUN npm install

COPY . .

# Set default API base URL for build time
ARG PUBLIC_API_BASE_URL=http://localhost:5001
ENV PUBLIC_API_BASE_URL=$PUBLIC_API_BASE_URL

RUN npm run build

EXPOSE 5173

CMD ["npm", "run", "preview", "--", "--host", "0.0.0.0", "--port", "5173"]
