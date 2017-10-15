FROM golang:1.9-alpine3.6

# Copy the local package files to the container's workspace.
ADD . /go/src/github.com/martin61/i2p-tools

# Make project CWD
WORKDIR /go/src/github.com/martin61/i2p-tools

# Build everything
RUN apk add --no-cache --update git && \
    go get && \
    apk del git
RUN go build -o /i2p-tools

CMD ["/i2p-tools"]
