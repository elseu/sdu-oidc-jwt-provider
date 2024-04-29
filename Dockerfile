FROM node:20-alpine

ADD . /app
WORKDIR /app

RUN npm i && npm run build && npm cache clean --force && rm -rf node_modules
RUN npm i --production

ENV PORT=80

EXPOSE 80
ENTRYPOINT ["npm", "start"]
