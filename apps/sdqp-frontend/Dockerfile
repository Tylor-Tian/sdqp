FROM node:22-alpine AS build

WORKDIR /app

COPY apps/sdqp-frontend/package.json ./
COPY apps/sdqp-frontend/package-lock.json ./

RUN npm ci

COPY apps/sdqp-frontend ./

RUN npm run build

FROM nginx:1.29-alpine AS runtime

COPY apps/sdqp-frontend/nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /app/dist /usr/share/nginx/html

EXPOSE 4173

HEALTHCHECK --interval=10s --timeout=5s --retries=12 CMD wget -q -O /dev/null http://127.0.0.1:4173/ || exit 1
