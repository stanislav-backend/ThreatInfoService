package core_http_request

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	core_errors "threatinfoservice/internal/core/errors"
)

const MaxRequestBodySize = 1024 * 1024

func DecodeJSON(w http.ResponseWriter, r *http.Request, dst any) error {
	r.Body = http.MaxBytesReader(
		w,
		r.Body,
		MaxRequestBodySize,
	)

	decoder := json.NewDecoder(r.Body)

	if err := decoder.Decode(dst); err != nil {
		return fmt.Errorf(
			"decode JSON request: %v: %w",err,
			core_errors.ErrInvalidArgument,
		)
	}

	var extra any

	if err := decoder.Decode(&extra); err != io.EOF {
		return fmt.Errorf(
			"request body must contain exactly one JSON value: %w",
			core_errors.ErrInvalidArgument,
		)
	}

	return nil
}