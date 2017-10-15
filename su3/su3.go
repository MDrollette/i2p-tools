package su3

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"strconv"
	"time"
)

const (
	minVersionLength = 16

	SigTypeDSA             = uint16(0)
	SigTypeECDSAWithSHA256 = uint16(1)
	SigTypeECDSAWithSHA384 = uint16(2)
	SigTypeECDSAWithSHA512 = uint16(3)
	SigTypeRSAWithSHA256   = uint16(4)
	SigTypeRSAWithSHA384   = uint16(5)
	SigTypeRSAWithSHA512   = uint16(6)

	ContentTypeUnknown = uint8(0)
	ContentTypeRouter  = uint8(1)
	ContentTypePlugin  = uint8(2)
	ContentTypeReseed  = uint8(3)
	ContentTypeNews    = uint8(4)

	FileTypeZIP   = uint8(0)
	FileTypeXML   = uint8(1)
	FileTypeHTML  = uint8(2)
	FileTypeXMLGZ = uint8(3)

	magicBytes = "I2Psu3"
)

type File struct {
	Format        uint8
	SignatureType uint16
	FileType      uint8
	ContentType   uint8

	Version     []byte
	SignerID    []byte
	Content     []byte
	Signature   []byte
	SignedBytes []byte
}

func New() *File {
	return &File{
		Version:       []byte(strconv.FormatInt(time.Now().Unix(), 10)),
		SignatureType: SigTypeRSAWithSHA512,
	}
}

func (s *File) Sign(privkey *rsa.PrivateKey) error {
	var hashType crypto.Hash
	switch s.SignatureType {
	case SigTypeDSA:
		hashType = crypto.SHA1
	case SigTypeECDSAWithSHA256, SigTypeRSAWithSHA256:
		hashType = crypto.SHA256
	case SigTypeECDSAWithSHA384, SigTypeRSAWithSHA384:
		hashType = crypto.SHA384
	case SigTypeECDSAWithSHA512, SigTypeRSAWithSHA512:
		hashType = crypto.SHA512
	default:
		return fmt.Errorf("unknown signature type: %d", s.SignatureType)
	}

	h := hashType.New()
	h.Write(s.BodyBytes())
	digest := h.Sum(nil)

	sig, err := rsa.SignPKCS1v15(rand.Reader, privkey, 0, digest)
	if nil != err {
		return err
	}

	s.Signature = sig

	return nil
}

func (s *File) BodyBytes() []byte {
	var (
		buf = new(bytes.Buffer)

		skip    [1]byte
		bigSkip [12]byte

		versionLength   = uint8(len(s.Version))
		signatureLength = uint16(512)
		signerIDLength  = uint8(len(s.SignerID))
		contentLength   = uint64(len(s.Content))
	)

	// determine sig length based on type
	switch s.SignatureType {
	case SigTypeDSA:
		signatureLength = uint16(40)
	case SigTypeECDSAWithSHA256, SigTypeRSAWithSHA256:
		signatureLength = uint16(256)
	case SigTypeECDSAWithSHA384, SigTypeRSAWithSHA384:
		signatureLength = uint16(384)
	case SigTypeECDSAWithSHA512, SigTypeRSAWithSHA512:
		signatureLength = uint16(512)
	}

	// pad the version field
	if len(s.Version) < minVersionLength {
		minBytes := make([]byte, minVersionLength)
		copy(minBytes, s.Version)
		s.Version = minBytes
		versionLength = uint8(len(s.Version))
	}

	binary.Write(buf, binary.BigEndian, []byte(magicBytes))
	binary.Write(buf, binary.BigEndian, skip)
	binary.Write(buf, binary.BigEndian, s.Format)
	binary.Write(buf, binary.BigEndian, s.SignatureType)
	binary.Write(buf, binary.BigEndian, signatureLength)
	binary.Write(buf, binary.BigEndian, skip)
	binary.Write(buf, binary.BigEndian, versionLength)
	binary.Write(buf, binary.BigEndian, skip)
	binary.Write(buf, binary.BigEndian, signerIDLength)
	binary.Write(buf, binary.BigEndian, contentLength)
	binary.Write(buf, binary.BigEndian, skip)
	binary.Write(buf, binary.BigEndian, s.FileType)
	binary.Write(buf, binary.BigEndian, skip)
	binary.Write(buf, binary.BigEndian, s.ContentType)
	binary.Write(buf, binary.BigEndian, bigSkip)
	binary.Write(buf, binary.BigEndian, s.Version)
	binary.Write(buf, binary.BigEndian, s.SignerID)
	binary.Write(buf, binary.BigEndian, s.Content)

	return buf.Bytes()
}

func (s *File) MarshalBinary() ([]byte, error) {
	buf := bytes.NewBuffer(s.BodyBytes())

	// append the signature
	binary.Write(buf, binary.BigEndian, s.Signature)

	return buf.Bytes(), nil
}

func (s *File) UnmarshalBinary(data []byte) error {
	var (
		r = bytes.NewReader(data)

		magic   = []byte(magicBytes)
		skip    [1]byte
		bigSkip [12]byte

		signatureLength uint16
		versionLength   uint8
		signerIDLength  uint8
		contentLength   uint64
	)

	binary.Read(r, binary.BigEndian, &magic)
	binary.Read(r, binary.BigEndian, &skip)
	binary.Read(r, binary.BigEndian, &s.Format)
	binary.Read(r, binary.BigEndian, &s.SignatureType)
	binary.Read(r, binary.BigEndian, &signatureLength)
	binary.Read(r, binary.BigEndian, &skip)
	binary.Read(r, binary.BigEndian, &versionLength)
	binary.Read(r, binary.BigEndian, &skip)
	binary.Read(r, binary.BigEndian, &signerIDLength)
	binary.Read(r, binary.BigEndian, &contentLength)
	binary.Read(r, binary.BigEndian, &skip)
	binary.Read(r, binary.BigEndian, &s.FileType)
	binary.Read(r, binary.BigEndian, &skip)
	binary.Read(r, binary.BigEndian, &s.ContentType)
	binary.Read(r, binary.BigEndian, &bigSkip)

	s.Version = make([]byte, versionLength)
	s.SignerID = make([]byte, signerIDLength)
	s.Content = make([]byte, contentLength)
	s.Signature = make([]byte, signatureLength)

	binary.Read(r, binary.BigEndian, &s.Version)
	binary.Read(r, binary.BigEndian, &s.SignerID)
	binary.Read(r, binary.BigEndian, &s.Content)
	binary.Read(r, binary.BigEndian, &s.Signature)

	return nil
}

func (s *File) VerifySignature(cert *x509.Certificate) error {
	var sigAlg x509.SignatureAlgorithm
	switch s.SignatureType {
	case SigTypeDSA:
		sigAlg = x509.DSAWithSHA1
	case SigTypeECDSAWithSHA256:
		sigAlg = x509.ECDSAWithSHA256
	case SigTypeECDSAWithSHA384:
		sigAlg = x509.ECDSAWithSHA384
	case SigTypeECDSAWithSHA512:
		sigAlg = x509.ECDSAWithSHA512
	case SigTypeRSAWithSHA256:
		sigAlg = x509.SHA256WithRSA
	case SigTypeRSAWithSHA384:
		sigAlg = x509.SHA384WithRSA
	case SigTypeRSAWithSHA512:
		sigAlg = x509.SHA512WithRSA
	default:
		return fmt.Errorf("unknown signature type: %d", s.SignatureType)
	}

	return checkSignature(cert, sigAlg, s.BodyBytes(), s.Signature)
}

func (s *File) String() string {
	var b bytes.Buffer

	// header
	fmt.Fprintln(&b, "---------------------------")
	fmt.Fprintf(&b, "Format: %q\n", s.Format)
	fmt.Fprintf(&b, "SignatureType: %q\n", s.SignatureType)
	fmt.Fprintf(&b, "FileType: %q\n", s.FileType)
	fmt.Fprintf(&b, "ContentType: %q\n", s.ContentType)
	fmt.Fprintf(&b, "Version: %q\n", bytes.Trim(s.Version, "\x00"))
	fmt.Fprintf(&b, "SignerId: %q\n", s.SignerID)
	fmt.Fprintf(&b, "---------------------------")

	// content & signature
	// fmt.Fprintf(&b, "Content: %q\n", s.Content)
	// fmt.Fprintf(&b, "Signature: %q\n", s.Signature)
	// fmt.Fprintln(&b, "---------------------------")

	return b.String()
}
