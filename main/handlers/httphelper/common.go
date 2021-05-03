package httphelper

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/go-chi/chi"
	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"
	"github.com/ubirch/ubirch-client-go/main/vars"
	"io/ioutil"
	"net/http"
	"strings"
)

type Sha256Sum [vars.HashLen]byte

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

// GetUUID returns the UUID parameter from the request URL
func GetUUID(r *http.Request) (uuid.UUID, error) {
	uuidParam := chi.URLParam(r, vars.UUIDKey)
	id, err := uuid.Parse(uuidParam)
	if err != nil {
		return uuid.Nil, fmt.Errorf("invalid UUID: \"%s\": %v", uuidParam, err)
	}
	return id, nil
}

// CheckAuth checks the auth token from the request header and returns it if valid
// Returns error if UUID is unknown or auth token is invalid
func CheckAuth(r *http.Request, actualAuth string) (string, error) {
	// check auth token from request header
	headerAuthToken := AuthToken(r.Header)
	if actualAuth != headerAuthToken {
		return "", fmt.Errorf("invalid auth token")
	}

	return headerAuthToken, nil
}

func readBody(r *http.Request) ([]byte, error) {
	rBody, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return nil, fmt.Errorf("unable to read request body: %v", err)
	}
	return rBody, nil
}

func isHashRequest(r *http.Request) bool {
	return strings.HasSuffix(r.URL.Path, vars.HashEndpoint)
}

// GetHash returns the hash from the request body
func GetHash(r *http.Request) (Sha256Sum, error) {
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
	case vars.JSONType:
		data, err = GetSortedCompactJSON(data)
		if err != nil {
			return Sha256Sum{}, err
		}
		log.Debugf("sorted compact JSON: %s", string(data))

		fallthrough
	case vars.BinType:
		// hash original data
		return sha256.Sum256(data), nil
	default:
		return Sha256Sum{}, fmt.Errorf("invalid content-type for original data: "+
			"expected (\"%s\" | \"%s\")", vars.BinType, vars.JSONType)
	}
}

func getHashFromHashRequest(header http.Header, data []byte) (hash Sha256Sum, err error) {
	switch ContentType(header) {
	case vars.TextType:
		if ContentEncoding(header) == vars.HexEncoding {
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
	case vars.BinType:
		if len(data) != vars.HashLen {
			return Sha256Sum{}, fmt.Errorf("invalid SHA256 hash size: "+
				"expected %d bytes, got %d bytes", vars.HashLen, len(data))
		}

		copy(hash[:], data)
		return hash, nil
	default:
		return Sha256Sum{}, fmt.Errorf("invalid content-type for hash: "+
			"expected (\"%s\" | \"%s\")", vars.BinType, vars.TextType)
	}
}

func jsonMarshal(v interface{}) ([]byte, error) {
	buffer := &bytes.Buffer{}
	encoder := json.NewEncoder(buffer)
	encoder.SetEscapeHTML(false)
	err := encoder.Encode(v)
	return buffer.Bytes(), err
}
// forwards response to sender
func SendResponse(w http.ResponseWriter, resp HTTPResponse) {
	for k, v := range resp.Header {
		w.Header().Set(k, v[0])
	}
	w.WriteHeader(resp.StatusCode)
	_, err := w.Write(resp.Content)
	if err != nil {
		log.Errorf("unable to write response: %s", err)
	}
}