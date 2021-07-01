package handlers

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/go-chi/chi"
	"github.com/google/uuid"
	h "github.com/ubirch/ubirch-client-go/main/adapters/httphelper"
	"github.com/ubirch/ubirch-client-go/main/vars"
	"net/http"

	log "github.com/sirupsen/logrus"
)

type Service interface {
	HandleRequest(w http.ResponseWriter, r *http.Request)
}

type ChainingService struct {
	*Signer
}

// Ensure ChainingService implements the Service interface
var _ Service = (*ChainingService)(nil)

func (s *ChainingService) HandleRequest(w http.ResponseWriter, r *http.Request) {
	var msg HTTPRequest
	var err error

	msg.ID, err = h.GetUUID(r)
	if err != nil {
		h.Error(msg.ID, w, err, http.StatusNotFound)
		return
	}

	exists, err := s.Exists(msg.ID)
	if err != nil {
		log.Errorf("%s: %v", msg.ID, err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	if !exists {
		h.Error(msg.ID, w, fmt.Errorf("unknown UUID"), http.StatusNotFound)
		return
	}

	msg.Auth = h.AuthToken(r.Header)

	ok, err := s.CheckAuthToken(msg.ID, msg.Auth)
	if err != nil {
		log.Errorf("%s: %v", msg.ID, err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	if !ok {
		h.Error(msg.ID, w, fmt.Errorf("invalid auth token"), http.StatusUnauthorized)
		return
	}

	msg.Hash, err = getHash(r)
	if err != nil {
		h.Error(msg.ID, w, err, http.StatusBadRequest)
		return
	}

	tx, identity, err := s.FetchIdentityWithLock(r.Context(), msg.ID)
	if err != nil {
		log.Errorf("%s: %v", msg.ID, err)
		http.Error(w, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
		return
	}

	resp := s.chain(msg, tx, identity)
	sendResponse(w, resp)
}

type SigningService struct {
	*Signer
}

var _ Service = (*SigningService)(nil)

func (s *SigningService) HandleRequest(w http.ResponseWriter, r *http.Request) {
	var msg HTTPRequest
	var err error

	msg.ID, err = h.GetUUID(r)
	if err != nil {
		h.Error(msg.ID, w, err, http.StatusNotFound)
		return
	}

	exists, err := s.Exists(msg.ID)
	if err != nil {
		log.Errorf("%s: %v", msg.ID, err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	if !exists {
		h.Error(msg.ID, w, fmt.Errorf("unknown UUID"), http.StatusNotFound)
		return
	}

	msg.Auth = h.AuthToken(r.Header)

	ok, err := s.CheckAuthToken(msg.ID, msg.Auth)
	if err != nil {
		log.Errorf("%s: %v", msg.ID, err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	if !ok {
		h.Error(msg.ID, w, fmt.Errorf("invalid auth token"), http.StatusUnauthorized)
		return
	}

	op, err := getOperation(r)
	if err != nil {
		h.Error(msg.ID, w, err, http.StatusNotFound)
		return
	}

	msg.Hash, err = getHash(r)
	if err != nil {
		h.Error(msg.ID, w, err, http.StatusBadRequest)
		return
	}

	resp := s.Sign(msg, op)
	sendResponse(w, resp)
}

type VerificationService struct {
	*Verifier
}

var _ Service = (*VerificationService)(nil)

func (v *VerificationService) HandleRequest(w http.ResponseWriter, r *http.Request) {
	hash, err := getHash(r)
	if err != nil {
		h.Error(uuid.Nil, w, err, http.StatusBadRequest)
		return
	}

	resp := v.Verify(hash[:])
	sendResponse(w, resp)
}

// getOperation returns the operation parameter from the request URL
func getOperation(r *http.Request) (operation, error) {
	opParam := chi.URLParam(r, vars.OperationKey)
	switch operation(opParam) {
	case anchorHash, disableHash, enableHash, deleteHash:
		return operation(opParam), nil
	default:
		return "", fmt.Errorf("invalid operation: "+
			"expected (\"%s\" | \"%s\" | \"%s\" | \"%s\"), got \"%s\"",
			anchorHash, disableHash, enableHash, deleteHash, opParam)
	}
}

func GetSortedCompactJSON(data []byte) ([]byte, error) {
	var reqDump interface{}
	var sortedCompactJson bytes.Buffer

	// json.Unmarshal returns an error if data is not valid JSON
	err := json.Unmarshal(data, &reqDump)
	if err != nil {
		return nil, fmt.Errorf("unable to parse JSON request body: %v", err)
	}
	// json.Marshal sorts the keys
	sortedJson, err := jsonMarshal(reqDump)
	if err != nil {
		return nil, fmt.Errorf("unable to serialize json object: %v", err)
	}
	// remove spaces and newlines
	err = json.Compact(&sortedCompactJson, sortedJson)
	if err != nil {
		return nil, fmt.Errorf("unable to compact json object: %v", err)
	}

	return sortedCompactJson.Bytes(), nil
}

func jsonMarshal(v interface{}) ([]byte, error) {
	buffer := &bytes.Buffer{}
	encoder := json.NewEncoder(buffer)
	encoder.SetEscapeHTML(false)
	err := encoder.Encode(v)
	return buffer.Bytes(), err
}
