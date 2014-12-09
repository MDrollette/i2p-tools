package su3

import (
	"archive/zip"
	"bytes"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"os"
)

const (
	MAGIC_BYTES = "I2Psu3"

	SIGTYPE_DSA          = uint16(0)
	SIGTYPE_ECDSA_SHA256 = uint16(1)
	SIGTYPE_ECDSA_SHA384 = uint16(2)
	SIGTYPE_ECDSA_SHA512 = uint16(3)
	SIGTYPE_RSA_SHA256   = uint16(4)
	SIGTYPE_RSA_SHA384   = uint16(5)
	SIGTYPE_RSA_SHA512   = uint16(6)

	CONTENT_TYPE_UNKNOWN = uint16(0)
	CONTENT_TYPE_ROUTER  = uint16(1)
	CONTENT_TYPE_PLUGIN  = uint16(2)
	CONTENT_TYPE_RESEED  = uint16(3)
	CONTENT_TYPE_NEWS    = uint16(4)

	FILE_TYPE_ZIP   = uint8(0)
	FILE_TYPE_XML   = uint8(1)
	FILE_TYPE_HTML  = uint8(2)
	FILE_TYPE_XMLGZ = uint8(3)
)

type Su3File struct {
	Magic           [6]byte
	Format          [1]byte
	SignatureType   uint16
	SignatureLength uint16
	VersionLength   uint8
	SignerIdLength  uint8
	ContentLength   uint64
	FileType        [1]byte
	ContentType     [1]byte

	Version     []byte
	SignerId    []byte
	Content     []byte
	Signature   []byte
	SignedBytes []byte
}

func (s *Su3File) String() string {
	var b bytes.Buffer

	// header
	fmt.Fprintln(&b, "---------------------------")

	fmt.Fprintf(&b, "Magic: %s\n", s.Magic)
	fmt.Fprintf(&b, "Format: %q\n", s.Format)
	fmt.Fprintf(&b, "SignatureType: %q\n", s.SignatureType)
	fmt.Fprintf(&b, "SignatureLength: %s\n", s.SignatureLength)
	fmt.Fprintf(&b, "VersionLength: %s\n", s.VersionLength)
	fmt.Fprintf(&b, "SignerIdLength: %s\n", s.SignerIdLength)
	fmt.Fprintf(&b, "ContentLength: %s\n", s.ContentLength)
	fmt.Fprintf(&b, "FileType: %q\n", s.FileType)
	fmt.Fprintf(&b, "ContentType: %q\n", s.ContentType)

	// content
	fmt.Fprintln(&b, "---------------------------")

	fmt.Fprintf(&b, "Version: %q\n", bytes.Trim(s.Version, "\x00"))
	fmt.Fprintf(&b, "SignerId: %q\n", s.SignerId)
	// fmt.Fprintf(&b, "Content: %q\n", s.Content)
	// fmt.Fprintf(&b, "Signature: %q\n", s.Signature)

	fmt.Fprintln(&b, "---------------------------")

	return b.String()
}

func (s *Su3File) VerifySignature() error {
	return verifySig(s.SignatureType, s.SignerId, s.Signature, s.SignedBytes)
}

func uzipData(c []byte) ([]byte, error) {
	input := bytes.NewReader(c)
	zipReader, err := zip.NewReader(input, int64(len(c)))
	if nil != err {
		return nil, err
	}

	var uncompressed []byte
	for _, f := range zipReader.File {
		rc, err := f.Open()
		if err != nil {
			panic(err)
		}
		uncompressed = append(uncompressed, []byte(f.Name+"\n")...)
		rc.Close()
	}

	return uncompressed, nil
}

func verifySig(sigType uint16, signer, signature, signed []byte) (err error) {
	var cert *x509.Certificate
	if cert, err = certForSigner(string(signer)); nil != err {
		return err
	}

	var sigAlg x509.SignatureAlgorithm
	switch sigType {
	case SIGTYPE_DSA:
		sigAlg = x509.DSAWithSHA1
	case SIGTYPE_ECDSA_SHA256:
		sigAlg = x509.ECDSAWithSHA256
	case SIGTYPE_ECDSA_SHA384:
		sigAlg = x509.ECDSAWithSHA384
	case SIGTYPE_ECDSA_SHA512:
		sigAlg = x509.ECDSAWithSHA512
	case SIGTYPE_RSA_SHA256:
		sigAlg = x509.SHA256WithRSA
	case SIGTYPE_RSA_SHA384:
		sigAlg = x509.SHA384WithRSA
	case SIGTYPE_RSA_SHA512:
		sigAlg = x509.SHA512WithRSA
	default:
		return fmt.Errorf("Unsupported signature type.")
	}

	return checkSignature(cert, sigAlg, signed, signature)
}

func ReadSu3(file *os.File, su3File *Su3File) error {
	var (
		skip    [1]byte
		bigSkip [12]byte
	)

	// 0-5
	binary.Read(file, binary.BigEndian, &su3File.Magic)
	// 6
	binary.Read(file, binary.BigEndian, &skip)
	// 7
	binary.Read(file, binary.BigEndian, &su3File.Format)
	// 8-9
	binary.Read(file, binary.BigEndian, &su3File.SignatureType)
	// 10-11
	binary.Read(file, binary.BigEndian, &su3File.SignatureLength)
	// 12
	binary.Read(file, binary.BigEndian, &skip)
	// 13
	binary.Read(file, binary.BigEndian, &su3File.VersionLength)
	// 14
	binary.Read(file, binary.BigEndian, &skip)
	// 15
	binary.Read(file, binary.BigEndian, &su3File.SignerIdLength)
	// 16-23
	binary.Read(file, binary.BigEndian, &su3File.ContentLength)
	// 24
	binary.Read(file, binary.BigEndian, &skip)
	// 25
	binary.Read(file, binary.BigEndian, &su3File.FileType)
	// 26
	binary.Read(file, binary.BigEndian, &skip)
	// 27
	binary.Read(file, binary.BigEndian, &su3File.ContentType)
	// 28-39
	binary.Read(file, binary.BigEndian, &bigSkip)

	su3File.Version = make([]byte, su3File.VersionLength)
	su3File.SignerId = make([]byte, su3File.SignerIdLength)
	su3File.Content = make([]byte, su3File.ContentLength)
	su3File.Signature = make([]byte, su3File.SignatureLength)

	// 40-55+  Version, UTF-8 padded with trailing 0x00, 16 bytes minimum, length specified at byte 13. Do not append 0x00 bytes if the length is 16 or more.
	binary.Read(file, binary.BigEndian, su3File.Version)
	// xx+ ID of signer, (e.g. "zzz@mail.i2p") UTF-8, not padded, length specified at byte 15
	binary.Read(file, binary.BigEndian, su3File.SignerId)
	// xx+ Content, length and format specified in header
	binary.Read(file, binary.BigEndian, su3File.Content)

	// re-read from the beginning to get the signed content
	signedEnd, _ := file.Seek(0, 1)
	file.Seek(0, 0)
	su3File.SignedBytes = make([]byte, signedEnd)
	binary.Read(file, binary.BigEndian, su3File.SignedBytes)

	// xx+ Signature, length specified in header, covers everything starting at byte 0
	binary.Read(file, binary.BigEndian, su3File.Signature)

	return nil
}
