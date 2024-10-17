FROM golang:alpine AS builder

RUN mkdir -p /go/src
ADD . /go/src

#Build Source
WORKDIR /go/src

RUN apk add --no-cache --update; \
    apk add git openssh; \
    apk add tzdata;

RUN go mod tidy
RUN go build -o main-app .

#Final Build Image
FROM alpine:latest
COPY --from=builder /usr/share/zoneinfo /usr/share/zoneinfo
COPY --from=builder /go/src/main-app /app/main-app
COPY ./params /app/params

WORKDIR /app

RUN mkdir params; \
    mkdir -p file/temp; \
    mkdir -p file/rbac; \
    mkdir -p file/storage

COPY ./migrations/sql/ migrations/sql

ENTRYPOINT ["/app/main-app"]
