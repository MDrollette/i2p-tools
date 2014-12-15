I2P Reseed Tools
==================

This tool provides a secure and efficient reseed server for the I2P network. There are several utility commands to create, sign, validate SU3 files and to check the status of the currently known public reseed servers.

## Installation

If you have Go installed you can download, build, and install this tool with `go get`

```
$ go get github.com/MDrollette/i2p-tools
...
$ i2p-tools -h
...
```

Otherwise, a binary for your OS can be downloaded from http://matt.i2p/

## Usage

If this is your first time running a reseed server (ie. you don't have any existing keys). You can simply run the following command and follow the prompts to create the appropriate keys and certificates.

```
$ i2p-tools reseed --signer=you@mail.i2p --tlsHost=your-domain.tld --netdb=/var/lib/i2p/i2p-config/netDb
...
```

This will start an HTTPS reseed server on the default port and generate 4 files in your current directory (a TLS key and certificate, and a signing key and certificate). Both of the certificates (*.crt) will need to be sent to the I2P developers in order for your reseed server to be included in the standard I2P package.
