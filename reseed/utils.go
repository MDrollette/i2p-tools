package reseed

import (
	"archive/zip"
	"bytes"
)

func zipSeeds(seeds Seed) ([]byte, error) {
	// Create a buffer to write our archive to.
	buf := new(bytes.Buffer)

	// Create a new zip archive.
	zipWriter := zip.NewWriter(buf)

	// Add some files to the archive.
	for _, file := range seeds {
		zipFile, err := zipWriter.Create(file.Name)
		if err != nil {
			return nil, err
		}
		_, err = zipFile.Write(file.Data)
		if err != nil {
			return nil, err
		}
	}

	if err := zipWriter.Close(); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

func uzipSeeds(c []byte) ([]byte, error) {
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
