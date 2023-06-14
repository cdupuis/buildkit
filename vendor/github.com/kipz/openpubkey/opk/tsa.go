package opk

import (
	"bytes"
	"crypto"
	"fmt"
	"io"
	"net/http"

	"github.com/digitorus/timestamp"
)

func CreateTimeStamp(digest *bytes.Reader) (*timestamp.Timestamp, error) {
	tsq, err := timestamp.CreateRequest(digest, &timestamp.RequestOptions{
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
		return nil, fmt.Errorf("Unhandled response code from TSA %d", tsr.StatusCode)
	}

	resp, err := io.ReadAll(tsr.Body)
	if err != nil {
		return nil, err
	}

	tsResp, err := timestamp.ParseResponse(resp)
	if err != nil {
		return nil, err
	}
	return tsResp, nil
}
