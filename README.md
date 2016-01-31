I2P Reseed Tools
==================

This tool provides a secure and efficient reseed server for the I2P network. There are several utility commands to create, sign, and validate SU3 files.

## Installation

If you have go installed you can download, build, and install this tool with `go get`

```
export GOPATH=$HOME/go; mkdir $GOPATH; cd $GOPATH
go get github.com/martin61/i2p-tools
bin/i2p-tools -h
```

## Usage

### Locally behind a webserver (reverse proxy setup), preferred:

```
GOPATH=$HOME/go; cd $GOPATH; bin/i2p-tools reseed --signer=you@mail.i2p --netdb=/home/i2p/.i2p/netDb --port=8443 --ip=127.0.0.1 --trustProxy
```

### Without webserver, standalone with tls support

```
GOPATH=$HOME/go; cd $GOPATH; bin/i2p-tools reseed --signer=you@mail.i2p --netdb=/home/i2p/.i2p/netDb --tlsHost=your-domain.tld
```

If this is your first time running a reseed server (ie. you don't have any existing keys), you can simply run the command and follow the prompts to create the appropriate keys and certificates.
Afterwards an HTTPS reseed server will start on the default port and generate 4 files in your current directory (a TLS key and certificate, and a signing key and certificate).
