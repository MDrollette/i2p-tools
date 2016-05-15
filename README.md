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

### Without a webserver, standalone with TLS support

```
GOPATH=$HOME/go; cd $GOPATH; bin/i2p-tools reseed --signer=you@mail.i2p --netdb=/home/i2p/.i2p/netDb --tlsHost=your-domain.tld
```

If this is your first time running a reseed server (ie. you don't have any existing keys), 
you can simply run the command and follow the prompts to create the appropriate keys, crl and certificates.
Afterwards an HTTPS reseed server will start on the default port and generate 6 files in your current directory 
(a TLS key, certificate and crl, and a su3-file signing key, certificate and crl).

Get the source code here on github or a pre-build binary anonymously on 

http://reseed.i2p/
http://j7xszhsjy7orrnbdys7yykrssv5imkn4eid7n5ikcnxuhpaaw6cq.b32.i2p/

also a short guide and complete tech info.
