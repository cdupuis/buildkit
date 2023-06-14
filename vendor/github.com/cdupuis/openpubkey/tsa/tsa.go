package tsa

import (
	"bytes"
	"crypto"
	"fmt"
	"io"
	"net/http"

	"github.com/digitorus/timestamp"
)

func CreateTimeStamp(payload []byte) ([]byte, error) {
	tsq, err := timestamp.CreateRequest(bytes.NewReader(payload), &timestamp.RequestOptions{
		Hash:         crypto.SHA256,
		Certificates: true,
	})
	if err != nil {
		return nil, err
	}

	tsr, err := http.Post("https://freetsa.org/tsr", "application/timestamp-query", bytes.NewReader(tsq))
	if err != nil {
		return nil, err
	}

	if tsr.StatusCode != 200 {
		return nil, fmt.Errorf("unhandled response code from TSA %d", tsr.StatusCode)
	}

	resp, err := io.ReadAll(tsr.Body)
	if err != nil {
		return nil, err
	}

	// verify the created timestamp
	_, err = timestamp.ParseResponse(resp)
	if err != nil {
		return nil, err
	}
	return resp, nil
}
