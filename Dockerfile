# syntax=docker/dockerfile:1
#
# Authvex server and Studio in one small image.
#
#   docker build -t authvex .
#   docker run --rm -v "$PWD/data:/data" authvex init          # scaffold a workspace in ./data
#   docker run -d -p 4320:4320 -v "$PWD/data:/data" authvex     # run it
#
# The workspace (config, tenants, users, signing keys, state) lives in /data. Put TLS in front of the container; set publicUrl and
# rpId in authvex.config.json. NOTE: this Dockerfile has not been built by the maintainers (no Docker on their machine); it
# follows the same pack-and-install path that scripts/smoke.mjs verifies. Report problems.

FROM node:24-bookworm-slim AS build
WORKDIR /src
COPY package.json package-lock.json tsconfig.base.json tsconfig.json next.config.ts postcss.config.mjs ./
COPY packages ./packages
COPY src ./src
COPY scripts ./scripts
RUN npm ci --no-audit --no-fund
RUN npm run build
RUN mkdir /out && npm pack --pack-destination /out -w @authvex/core -w @authvex/cli --silent

FROM node:24-bookworm-slim
ENV NODE_ENV=production
WORKDIR /app
COPY --from=build /out /tmp/pkg
RUN npm install --omit=dev --no-audit --no-fund /tmp/pkg/authvex-core-*.tgz /tmp/pkg/authvex-cli-*.tgz \
    && rm -rf /tmp/pkg /root/.npm \
    && mkdir /data && chown node:node /data
USER node
WORKDIR /data
VOLUME ["/data"]
EXPOSE 4320
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:4320/api/health').then(r=>process.exit(r.ok?0:1),()=>process.exit(1))"
ENTRYPOINT ["/app/node_modules/.bin/authvex"]
CMD ["studio", "--host", "0.0.0.0", "--port", "4320"]
