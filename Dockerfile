FROM golang:1.24

WORKDIR /app

COPY bin/backend /app/backend
COPY internal/database/migrations /app/migrations
COPY internal/casbin/model.conf /app/model.conf
COPY internal/casbin/full_policy.csv /app/policy.csv

EXPOSE 8080

CMD ["/app/backend"]