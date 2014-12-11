package reseed

import (
	"archive/zip"
	"bytes"
	"io/ioutil"
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

func uzipSeeds(c []byte) (Seed, error) {
	input := bytes.NewReader(c)
	zipReader, err := zip.NewReader(input, int64(len(c)))
	if nil != err {
		return nil, err
	}

	var seeds Seed
	for _, f := range zipReader.File {
		rc, err := f.Open()
		if err != nil {
			return nil, err
		}
		data, err := ioutil.ReadAll(rc)
		rc.Close()
		if nil != err {
			return nil, err
		}

		seeds = append(seeds, routerInfo{Name: f.Name, Data: data})
	}

	return seeds, nil
}
