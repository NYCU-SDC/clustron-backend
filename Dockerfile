FROM golang:1.24

WORKDIR /app

COPY bin/backend /app/backend

EXPOSE 8080

CMD ["/app/backend"]