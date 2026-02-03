ARG BUILD_FROM=alpine:3.23.3
FROM $BUILD_FROM

# Install Node.js and WireGuard tools (Alpine-based images commonly used for HA add-ons)
# Home Assistant build system provides BUILD_FROM as an Alpine image.
RUN apk add --no-cache nodejs npm wireguard-tools iproute2 util-linux

WORKDIR /app

COPY package.json tsconfig.json config.yaml ./
COPY src/ ./src/

RUN npm ci --omit=dev=false || npm i
RUN npm run build
RUN npm prune --omit=dev

CMD [ "/usr/bin/node", "/app/dist/index.js" ]
