FROM golang:1.4.2

# Copy the local package files to the container's workspace.
ADD . /go/src/github.com/martin61/i2p-tools

# Make project CWD
WORKDIR /go/src/github.com/martin61/i2p-tools

# Build everything
RUN go get
RUN go build -o /i2p-tools

CMD ["/i2p-tools"]
