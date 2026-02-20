FROM ghcr.io/puppeteer/puppeteer:latest

WORKDIR /app
USER root

# copy trước package.json để cache install
COPY package*.json ./

# ép cài tất cả dependencies bao gồm dev
ENV NODE_ENV=development
RUN npm install --include=dev && npm install -g nodemon

# copy toàn bộ source
COPY . .

EXPOSE 3000 9229

# giữ debug mode
CMD ["nodemon", "--inspect=0.0.0.0:9229", "server.js"]
