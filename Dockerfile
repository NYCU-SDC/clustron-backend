FROM ubuntu

# 環境變數
ENV GOLANG_VERSION=1.24.2
ENV GO_DOWNLOAD_URL=https://go.dev/dl/go${GOLANG_VERSION}.linux-amd64.tar.gz
ENV GOROOT=/usr/local/go
ENV GOPATH=/go
ENV PATH=$GOROOT/bin:$GOPATH/bin:$PATH

# 安裝必要工具 + 安裝 Go
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl ca-certificates build-essential \
    && curl -fsSL "$GO_DOWNLOAD_URL" -o go.tar.gz \
    && rm -rf /usr/local/go \
    && tar -C /usr/local -xzf go.tar.gz \
    && rm go.tar.gz \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# 建立 GOPATH
RUN mkdir -p "$GOPATH"/{bin,pkg,src}

WORKDIR /app

COPY bin/backend /app/backend
COPY internal/database/migrations /app/migrations
COPY internal/casbin/model.conf /app/model.conf
COPY internal/casbin/full_policy.csv /app/policy.csv

EXPOSE 8080

CMD ["/app/backend"]