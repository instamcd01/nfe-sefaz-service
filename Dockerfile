# Deploy via Easypanel, mesma VPS do n8n e do gestor-loja.
FROM node:22-alpine

WORKDIR /app
COPY package.json ./
RUN npm install --omit=dev

COPY src ./src

EXPOSE 3000
ENV PORT=3000

CMD ["node", "src/index.js"]
