FROM node:22-alpine
WORKDIR /fixture
COPY package.json .
RUN npm install --omit=dev
COPY . .
RUN node app.js --export
EXPOSE 8080
CMD ["node","app.js"]
