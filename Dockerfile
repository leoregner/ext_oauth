FROM node:10.9.0-jessie
MAINTAINER office@leoregner.eu
EXPOSE 80

WORKDIR /data
COPY src .
RUN npm install
CMD node index.js > /dev/stdout 2> /dev/stderr