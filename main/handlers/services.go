package handlers

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"

	"github.com/go-chi/chi"
	"github.com/google/uuid"

	log "github.com/sirupsen/logrus"
)

const (
	UUIDKey      = "uuid"
	OperationKey = "operation"
	VerifyPath   = "verify"
	HashEndpoint = "hash"

	BinType  = "application/octet-stream"
	TextType = "text/plain"
	JSONType = "application/json"

	HexEncoding = "hex"

	HashLen = 32
)

type Service interface {
	HandleRequest(w http.ResponseWriter, r *http.Request)
}

type Sha256Sum [HashLen]byte

type HTTPRequest struct {
	ID   uuid.UUID
	Auth string
	Hash Sha256Sum
}

type HTTPResponse struct {
	StatusCode int         `json:"statusCode"`
	Header     http.Header `json:"header"`
	Content    []byte      `json:"content"`
}

type ChainingService struct {
	*Signer
}

// Ensure ChainingService implements the Service interface
var _ Service = (*ChainingService)(nil)

func (s *ChainingService) HandleRequest(w http.ResponseWriter, r *http.Request) {
	var msg HTTPRequest
	var err error

	msg.ID, err = getUUID(r)
	if err != nil {
		Error(msg.ID, w, err, http.StatusNotFound)
		return
	}

	log.Debugf("%s: incomming chaining request", msg.ID)

	exists, err := s.checkExists(msg.ID)
	if err != nil {
		log.Errorf("%s: %v", msg.ID, err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	if !exists {
		Error(msg.ID, w, fmt.Errorf("unknown UUID"), http.StatusNotFound)
		return
	}

	idAuth, err := s.getAuth(msg.ID)
	if err != nil {
		log.Errorf("%s: %v", msg.ID, err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	msg.Auth, err = checkAuth(r, idAuth)
	if err != nil {
		Error(msg.ID, w, err, http.StatusUnauthorized)
		return
	}

	msg.Hash, err = getHash(r)
	if err != nil {
		Error(msg.ID, w, err, http.StatusBadRequest)
		return
	}

	tx, err := s.Protocol.StartTransactionWithLock(r.Context(), msg.ID)
	if err != nil {
		log.Errorf("%s: starting transaction with lock failed: %v", msg.ID, err)
		http.Error(w, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
		return
	}

	resp := s.chain(tx, msg)
	sendResponse(w, resp)
}

type SigningService struct {
	*Signer
}

var _ Service = (*SigningService)(nil)

func (s *SigningService) HandleRequest(w http.ResponseWriter, r *http.Request) {
	var msg HTTPRequest
	var err error

	msg.ID, err = getUUID(r)
	if err != nil {
		Error(msg.ID, w, err, http.StatusNotFound)
		return
	}

	exists, err := s.checkExists(msg.ID)
	if err != nil {
		log.Errorf("%s: %v", msg.ID, err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	if !exists {
		Error(msg.ID, w, fmt.Errorf("unknown UUID"), http.StatusNotFound)
		return
	}

	idAuth, err := s.getAuth(msg.ID)
	if err != nil {
		log.Errorf("%s: %v", msg.ID, err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	msg.Auth, err = checkAuth(r, idAuth)
	if err != nil {
		Error(msg.ID, w, err, http.StatusUnauthorized)
		return
	}

	op, err := getOperation(r)
	if err != nil {
		Error(msg.ID, w, err, http.StatusNotFound)
		return
	}

	msg.Hash, err = getHash(r)
	if err != nil {
		Error(msg.ID, w, err, http.StatusBadRequest)
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
		Error(uuid.Nil, w, err, http.StatusBadRequest)
		return
	}

	resp := v.Verify(hash[:])
	sendResponse(w, resp)
}

// wrapper for http.Error that additionally logs the error message to std.Output
func Error(uid uuid.UUID, w http.ResponseWriter, err error, code int) {
	log.Warnf("%s: %v", uid, err)
	http.Error(w, err.Error(), code)
}

// helper function to get "Content-Type" from request header
func ContentType(header http.Header) string {
	return strings.ToLower(header.Get("Content-Type"))
}

// helper function to get "Content-Transfer-Encoding" from request header
func ContentEncoding(header http.Header) string {
	return strings.ToLower(header.Get("Content-Transfer-Encoding"))
}

// helper function to get "X-Auth-Token" from request header
func AuthToken(header http.Header) string {
	return header.Get("X-Auth-Token")
}

// getUUID returns the UUID parameter from the request URL
func getUUID(r *http.Request) (uuid.UUID, error) {
	uuidParam := chi.URLParam(r, UUIDKey)
	id, err := uuid.Parse(uuidParam)
	if err != nil {
		return uuid.Nil, fmt.Errorf("invalid UUID: \"%s\": %v", uuidParam, err)
	}
	return id, nil
}

// checkAuth compares the auth token from the request header with a given string and returns it if valid
// Returns error if auth token is invalid
func checkAuth(r *http.Request, actualAuth string) (string, error) {
	headerAuthToken := AuthToken(r.Header)
	if actualAuth != headerAuthToken {
		return "", fmt.Errorf("invalid auth token")
	}

	return headerAuthToken, nil
}

// getOperation returns the operation parameter from the request URL
func getOperation(r *http.Request) (operation, error) {
	opParam := chi.URLParam(r, OperationKey)
	switch operation(opParam) {
	case anchorHash, disableHash, enableHash, deleteHash:
		return operation(opParam), nil
	default:
		return "", fmt.Errorf("invalid operation: "+
			"expected (\"%s\" | \"%s\" | \"%s\" | \"%s\"), got \"%s\"",
			anchorHash, disableHash, enableHash, deleteHash, opParam)
	}
}

func readBody(r *http.Request) ([]byte, error) {
	rBody, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return nil, fmt.Errorf("unable to read request body: %v", err)
	}
	return rBody, nil
}

func isHashRequest(r *http.Request) bool {
	return strings.HasSuffix(r.URL.Path, HashEndpoint)
}

// getHash returns the hash from the request body
func getHash(r *http.Request) (Sha256Sum, error) {
	rBody, err := readBody(r)
	if err != nil {
		return Sha256Sum{}, err
	}

	if isHashRequest(r) { // request contains hash
		return getHashFromHashRequest(r.Header, rBody)
	} else { // request contains original data
		return getHashFromDataRequest(r.Header, rBody)
	}
}

func getHashFromDataRequest(header http.Header, data []byte) (hash Sha256Sum, err error) {
	switch ContentType(header) {
	case JSONType:
		data, err = GetSortedCompactJSON(data)
		if err != nil {
			return Sha256Sum{}, err
		}
		log.Debugf("sorted compact JSON: %s", string(data))

		fallthrough
	case BinType:
		// hash original data
		return sha256.Sum256(data), nil
	default:
		return Sha256Sum{}, fmt.Errorf("invalid content-type for original data: "+
			"expected (\"%s\" | \"%s\")", BinType, JSONType)
	}
}

func getHashFromHashRequest(header http.Header, data []byte) (hash Sha256Sum, err error) {
	switch ContentType(header) {
	case TextType:
		if ContentEncoding(header) == HexEncoding {
			data, err = hex.DecodeString(string(data))
			if err != nil {
				return Sha256Sum{}, fmt.Errorf("decoding hex encoded hash failed: %v (%s)", err, string(data))
			}
		} else {
			data, err = base64.StdEncoding.DecodeString(string(data))
			if err != nil {
				return Sha256Sum{}, fmt.Errorf("decoding base64 encoded hash failed: %v (%s)", err, string(data))
			}
		}
		fallthrough
	case BinType:
		if len(data) != HashLen {
			return Sha256Sum{}, fmt.Errorf("invalid SHA256 hash size: "+
				"expected %d bytes, got %d bytes", HashLen, len(data))
		}

		copy(hash[:], data)
		return hash, nil
	default:
		return Sha256Sum{}, fmt.Errorf("invalid content-type for hash: "+
			"expected (\"%s\" | \"%s\")", BinType, TextType)
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

// forwards response to sender
func sendResponse(w http.ResponseWriter, resp HTTPResponse) {
	for k, v := range resp.Header {
		w.Header().Set(k, v[0])
	}
	w.WriteHeader(resp.StatusCode)
	_, err := w.Write(resp.Content)
	if err != nil {
		log.Errorf("unable to write response: %s", err)
	}
}
