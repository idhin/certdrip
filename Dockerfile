FROM golang:1.22-alpine

WORKDIR /app

RUN apk add --no-cache git

COPY go.mod ./
COPY go.sum ./
COPY main.go ./

RUN go mod tidy
RUN go build -o certstream-clone

EXPOSE 8080

CMD ["./certstream-clone"]
