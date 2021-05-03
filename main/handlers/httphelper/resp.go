package httphelper

import (
	"fmt"
	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"
	"net/http"
)

func EmptyOk(w http.ResponseWriter) error {
	w.Header().Set(HeaderContentType, MimeTextPlain)
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, "")
	return nil
}

func Ok(w http.ResponseWriter, rsp string) error {
	w.Header().Set(HeaderContentType, MimeTextPlain)
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, rsp)
	return nil
}

func ErrorResponse(code int, message string) HTTPResponse {
	if message == "" {
		message = http.StatusText(code)
	}
	return HTTPResponse{
		StatusCode: code,
		Header:     http.Header{"Content-Type": {"text/plain; charset=utf-8"}},
		Content:    []byte(message),
	}
}

// wrapper for http.Error that additionally logs the error message to std.Output
func Error(uid uuid.UUID, w http.ResponseWriter, err error, code int) {
	log.Warnf("%s: %v", uid, err)
	http.Error(w, err.Error(), code)
}
