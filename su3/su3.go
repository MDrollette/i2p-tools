package su3

type Su3 struct {
	// 0-5 Magic number "I2Psu3"
	Magic [6]byte

	// 6   unused = 0
	Unused1 [1]byte

	// 7   su3 file format version = 0
	Format [1]byte

	// 8-9 Signature type
	// 0x0000 = DSA-160
	// 0x0001 = ECDSA-SHA256-P256
	// 0x0002 = ECDSA-SHA384-P384
	// 0x0003 = ECDSA-SHA512-P521
	// 0x0004 = RSA-SHA256-2048
	// 0x0005 = RSA-SHA384-3072
	// 0x0006 = RSA-SHA512-4096
	SignatureType [2]byte

	// 10-11   Signature length, e.g. 40 (0x0028) for DSA-160
	SignatureLength [2]byte

	// 12  unused
	Unused2 [1]byte

	// 13  Version length (in bytes not chars, including padding) must be at least 16 (0x10) for compatibility
	VersionLength [1]byte

	// 14  unused
	Unused3 [1]byte

	// 15  Signer ID length (in bytes not chars)
	SignerIdLength [1]byte

	// 16-23   Content length (not including header or sig)
	ContentLength [8]byte

	// 24  unused
	Unused4 [1]byte

	// 25  File type
	// 0x00 = zip file
	// 0x01 = xml file (as of 0.9.15)
	// 0x02 = html file (as of 0.9.17)
	// 0x03 = xml.gz file (as of 0.9.17)
	FileType [1]byte

	// 26  unused
	Unused5 [1]byte

	// 27  Content type
	// 0x00 = unknown
	// 0x01 = router update
	// 0x02 = plugin or plugin update
	// 0x03 = reseed data
	// 0x04 = news feed (as of 0.9.15)
	ContentType [1]byte

	// 28-39   unused
	Unused6 [12]byte

	// 40-55+  Version, UTF-8 padded with trailing 0x00, 16 bytes minimum, length specified at byte 13. Do not append 0x00 bytes if the length is 16 or more.
	// xx+ ID of signer, (e.g. "zzz@mail.i2p") UTF-8, not padded, length specified at byte 15
	// xx+ Content, length and format specified in header
	// xx+ Signature, length specified in header, covers everything starting at byte 0
	Version [16]byte
}
