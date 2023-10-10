FROM alpine:latest

RUN apk add --no-cache --update bash curl

COPY . .

EXPOSE 80

CMD ["./ca"]
