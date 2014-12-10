package su3

import (
	"archive/zip"
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"os"
	"strconv"
	"time"
)

const (
	MIN_VERSION_LENGTH = 16

	SIGTYPE_DSA          = uint16(0)
	SIGTYPE_ECDSA_SHA256 = uint16(1)
	SIGTYPE_ECDSA_SHA384 = uint16(2)
	SIGTYPE_ECDSA_SHA512 = uint16(3)
	SIGTYPE_RSA_SHA256   = uint16(4)
	SIGTYPE_RSA_SHA384   = uint16(5)
	SIGTYPE_RSA_SHA512   = uint16(6)

	CONTENT_TYPE_UNKNOWN = uint8(0)
	CONTENT_TYPE_ROUTER  = uint8(1)
	CONTENT_TYPE_PLUGIN  = uint8(2)
	CONTENT_TYPE_RESEED  = uint8(3)
	CONTENT_TYPE_NEWS    = uint8(4)

	FILE_TYPE_ZIP   = uint8(0)
	FILE_TYPE_XML   = uint8(1)
	FILE_TYPE_HTML  = uint8(2)
	FILE_TYPE_XMLGZ = uint8(3)
)

var (
	MAGIC_BYTES = []byte("I2Psu3")
)

type Su3File struct {
	Format        uint8
	SignatureType uint16
	FileType      uint8
	ContentType   uint8

	Version     []byte
	SignerId    []byte
	Content     []byte
	Signature   []byte
	SignedBytes []byte
}

func NewSu3File() *Su3File {
	s := Su3File{
		Version:       []byte(strconv.FormatInt(time.Now().Unix(), 10)),
		SignatureType: SIGTYPE_RSA_SHA512,
	}

	return &s
}

func (s *Su3File) Sign(privkey *rsa.PrivateKey) error {
	var hashType crypto.Hash
	switch s.SignatureType {
	case SIGTYPE_DSA:
		hashType = crypto.SHA1
	case SIGTYPE_ECDSA_SHA256, SIGTYPE_RSA_SHA256:
		hashType = crypto.SHA256
	case SIGTYPE_ECDSA_SHA384, SIGTYPE_RSA_SHA384:
		hashType = crypto.SHA384
	case SIGTYPE_ECDSA_SHA512, SIGTYPE_RSA_SHA512:
		hashType = crypto.SHA512
	default:
		return fmt.Errorf("Unknown signature type")
	}

	h := hashType.New()
	h.Write(s.ContentBytes())
	digest := h.Sum(nil)

	sig, err := rsa.SignPKCS1v15(rand.Reader, privkey, 0, digest)
	if nil != err {
		return err
	}

	s.Signature = sig

	return nil
}

func (s *Su3File) ContentBytes() []byte {
	buf := new(bytes.Buffer)

	var (
		skip    [1]byte
		bigSkip [12]byte

		versionLength   = uint8(len(s.Version))
		signatureLength = uint16(40)
		signerIdLength  = uint8(len(s.SignerId))
		contentLength   = uint64(len(s.Content))
	)

	switch s.SignatureType {
	case SIGTYPE_DSA:
		signatureLength = uint16(40)
	case SIGTYPE_ECDSA_SHA256, SIGTYPE_RSA_SHA256:
		signatureLength = uint16(256)
	case SIGTYPE_ECDSA_SHA384, SIGTYPE_RSA_SHA384:
		signatureLength = uint16(384)
	case SIGTYPE_ECDSA_SHA512, SIGTYPE_RSA_SHA512:
		signatureLength = uint16(512)
	}

	// pad the version field
	if len(s.Version) < MIN_VERSION_LENGTH {
		minBytes := make([]byte, MIN_VERSION_LENGTH)
		copy(minBytes, s.Version)
		s.Version = minBytes
		versionLength = uint8(len(s.Version))
	}

	// 0-5
	binary.Write(buf, binary.BigEndian, MAGIC_BYTES)
	// 6
	binary.Write(buf, binary.BigEndian, skip)
	// 7
	binary.Write(buf, binary.BigEndian, s.Format)
	// 8-9
	binary.Write(buf, binary.BigEndian, s.SignatureType)
	// 10-11
	binary.Write(buf, binary.BigEndian, signatureLength)
	// 12
	binary.Write(buf, binary.BigEndian, skip)
	// 13
	binary.Write(buf, binary.BigEndian, versionLength)
	// 14
	binary.Write(buf, binary.BigEndian, skip)
	// 15
	binary.Write(buf, binary.BigEndian, signerIdLength)
	// 16-23
	binary.Write(buf, binary.BigEndian, contentLength)
	// 24
	binary.Write(buf, binary.BigEndian, skip)
	// 25
	binary.Write(buf, binary.BigEndian, s.FileType)
	// 26
	binary.Write(buf, binary.BigEndian, skip)
	// 27
	binary.Write(buf, binary.BigEndian, s.ContentType)
	// 28-39
	binary.Write(buf, binary.BigEndian, bigSkip)
	// 40-55+  Version, UTF-8 padded with trailing 0x00, 16 bytes minimum, length specified at byte 13. Do not append 0x00 bytes if the length is 16 or more.
	binary.Write(buf, binary.BigEndian, s.Version)
	// xx+ ID of signer, (e.g. "zzz@mail.i2p") UTF-8, not padded, length specified at byte 15
	binary.Write(buf, binary.BigEndian, s.SignerId)
	// xx+ Content, length and format specified in header
	binary.Write(buf, binary.BigEndian, s.Content)

	return buf.Bytes()
}

func (s *Su3File) Bytes() []byte {
	buf := new(bytes.Buffer)
	buf.Write(s.ContentBytes())

	// xx+ Signature, length specified in header, covers everything starting at byte 0
	binary.Write(buf, binary.BigEndian, s.Signature)

	return buf.Bytes()
}

func (s *Su3File) VerifySignature() error {
	var sigAlg x509.SignatureAlgorithm
	switch s.SignatureType {
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

	if cert, err := signerCertificate(string(s.SignerId)); nil != err {
		return err
	} else {
		return checkSignature(cert, sigAlg, s.ContentBytes(), s.Signature)
	}
}

func (s *Su3File) String() string {
	var b bytes.Buffer

	// header
	fmt.Fprintln(&b, "---------------------------")
	fmt.Fprintf(&b, "Format: %q\n", s.Format)
	fmt.Fprintf(&b, "SignatureType: %q\n", s.SignatureType)
	fmt.Fprintf(&b, "FileType: %q\n", s.FileType)
	fmt.Fprintf(&b, "ContentType: %q\n", s.ContentType)
	fmt.Fprintf(&b, "Version: %q\n", bytes.Trim(s.Version, "\x00"))
	fmt.Fprintf(&b, "SignerId: %q\n", s.SignerId)
	fmt.Fprintln(&b, "---------------------------")

	// content & signature
	// fmt.Fprintf(&b, "Content: %q\n", s.Content)
	// fmt.Fprintf(&b, "Signature: %q\n", s.Signature)
	// fmt.Fprintln(&b, "---------------------------")

	return b.String()
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

func ReadSu3(file *os.File) (*Su3File, error) {
	var (
		s = Su3File{}

		skip    uint8
		bigSkip [12]byte

		signatureLength uint16
		versionLength   uint8
		signerIdLength  uint8
		contentLength   uint64
		magic           [6]byte
	)

	// 0-5
	binary.Read(file, binary.BigEndian, &magic)
	// 6
	binary.Read(file, binary.BigEndian, &skip)
	// 7
	binary.Read(file, binary.BigEndian, &s.Format)
	// 8-9
	binary.Read(file, binary.BigEndian, &s.SignatureType)
	// 10-11
	binary.Read(file, binary.BigEndian, &signatureLength)
	// 12
	binary.Read(file, binary.BigEndian, &skip)
	// 13
	binary.Read(file, binary.BigEndian, &versionLength)
	// 14
	binary.Read(file, binary.BigEndian, &skip)
	// 15
	binary.Read(file, binary.BigEndian, &signerIdLength)
	// 16-23
	binary.Read(file, binary.BigEndian, &contentLength)
	// 24
	binary.Read(file, binary.BigEndian, &skip)
	// 25
	binary.Read(file, binary.BigEndian, &s.FileType)
	// 26
	binary.Read(file, binary.BigEndian, &skip)
	// 27
	binary.Read(file, binary.BigEndian, &s.ContentType)
	// 28-39
	binary.Read(file, binary.BigEndian, &bigSkip)

	s.Version = make([]byte, versionLength)
	s.SignerId = make([]byte, signerIdLength)
	s.Content = make([]byte, contentLength)
	s.Signature = make([]byte, signatureLength)

	// 40-55+  Version, UTF-8 padded with trailing 0x00, 16 bytes minimum, length specified at byte 13. Do not append 0x00 bytes if the length is 16 or more.
	binary.Read(file, binary.BigEndian, &s.Version)
	// xx+ ID of signer, (e.g. "zzz@mail.i2p") UTF-8, not padded, length specified at byte 15
	binary.Read(file, binary.BigEndian, &s.SignerId)
	// xx+ Content, length and format specified in header
	binary.Read(file, binary.BigEndian, &s.Content)
	// xx+ Signature, length specified in header, covers everything starting at byte 0
	binary.Read(file, binary.BigEndian, &s.Signature)

	return &s, nil
}
