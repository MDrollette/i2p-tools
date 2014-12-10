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
