FROM golang:1.24

WORKDIR ./app

COPY . .

RUN go mod tidy && go build -o bin/backend ./cmd/backend/main.go

EXPOSE 8080

CMD ["./bin/backend"]