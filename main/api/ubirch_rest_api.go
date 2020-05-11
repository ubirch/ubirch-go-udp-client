package api

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi"
	"github.com/google/uuid"
)

const (
	UUIDKey  = "uuid"
	BinType  = "application/octet-stream"
	JSONType = "application/json"
)

type HTTPServer struct {
	MessageHandler chan HTTPMessage
	AuthTokens     map[string]string
}

type HTTPMessage struct {
	ID       uuid.UUID
	Data     []byte
	Response chan HTTPResponse
}

type HTTPResponse struct {
	Code    int
	Header  map[string][]string
	Content []byte
}

func logError(err error) {
	log.Printf("HTTP SERVER ERROR: %s", err)
}

// helper function to get "content-type" from headers
func ContentType(r *http.Request) string {
	return strings.ToLower(r.Header.Get("content-type"))
}

// make sure request has correct content-type
func assertContentType(w http.ResponseWriter, r *http.Request, expectedType string) error {
	if ContentType(r) != expectedType {
		err := fmt.Sprintf("Wrong content-type. Expected \"%s\"", expectedType)
		http.Error(w, err, http.StatusBadRequest)
		return fmt.Errorf(err)
	}

	return nil
}

// helper function to get "x-auth-token" from headers
func XAuthToken(r *http.Request) string {
	return r.Header.Get("x-auth-token")
}

// get UUID from request URL and check auth token
func checkAuth(w http.ResponseWriter, r *http.Request, AuthTokens map[string]string) (uuid.UUID, error) {
	// get UUID from URL
	urlParam := chi.URLParam(r, UUIDKey)
	id, err := uuid.Parse(urlParam)
	if err != nil {
		err := fmt.Sprintf("unable to parse \"%s\" as UUID: %s", urlParam, err)
		http.Error(w, err, http.StatusNotFound)
		return uuid.Nil, fmt.Errorf(err)
	}

	// check if UUID is known
	idAuthToken, exists := AuthTokens[id.String()]
	if !exists {
		err := fmt.Sprintf("unknown UUID \"%s\"", id.String())
		http.Error(w, err, http.StatusNotFound)
		return uuid.Nil, fmt.Errorf(err)
	}

	// check authorization
	if XAuthToken(r) != idAuthToken {
		err := "invalid \"X-Auth-Token\""
		http.Error(w, err, http.StatusUnauthorized)
		return uuid.Nil, fmt.Errorf(err)
	}

	return id, err
}

func getSortedCompactJSON(w http.ResponseWriter, data []byte) ([]byte, error) {
	var reqDump interface{}
	var compactSortedJson bytes.Buffer

	// json.Unmarshal returns an error if data is not valid JSON
	err := json.Unmarshal(data, &reqDump)
	if err != nil {
		err := fmt.Sprintf("unable to parse request body: %v", err)
		http.Error(w, err, http.StatusBadRequest)
		return nil, fmt.Errorf(err)
	}
	// json.Marshal sorts the keys
	sortedJson, err := json.Marshal(reqDump)
	if err != nil {
		err := fmt.Sprintf("unable to serialize json object: %v", err)
		http.Error(w, err, http.StatusBadRequest)
		return nil, fmt.Errorf(err)
	}
	// remove spaces and newlines
	err = json.Compact(&compactSortedJson, sortedJson)
	if err != nil {
		err := fmt.Sprintf("unable to compact json object: %v", err)
		http.Error(w, err, http.StatusBadRequest)
		return nil, fmt.Errorf(err)
	}

	return compactSortedJson.Bytes(), err
}

func getData(w http.ResponseWriter, r *http.Request, isHash bool) ([]byte, error) {
	// read request body
	data, err := ioutil.ReadAll(r.Body)
	if err != nil {
		err := fmt.Sprintf("unable to read request body: %v", err)
		http.Error(w, err, http.StatusBadRequest)
		return nil, fmt.Errorf(err)
	}

	if ContentType(r) == JSONType {
		// generate a sorted compact rendering of the json formatted request body
		data, err = getSortedCompactJSON(w, data)
		if err != nil {
			return nil, err
		}
		// TODO
		//// only log original data if in debug-mode and never on production stage
		//if Debug && Env != PROD_STAGE {
		//	log.Printf("compact sorted json (go): %s", string(data))
		//}
	}

	if !isHash {
		hash := sha256.Sum256(data)
		data = hash[:]
	}

	return data, err
}

// blocks until response is received and forwards it to sender	// TODO go
func forwardBackendResponse(w http.ResponseWriter, respChan chan HTTPResponse) {
	resp := <-respChan
	w.WriteHeader(resp.Code)
	for k, v := range resp.Header {
		w.Header().Set(k, v[0])
	}
	_, err := w.Write(resp.Content)
	if err != nil {
		logError(fmt.Errorf("unable to write response: %s", err))
	}
}

func (srv *HTTPServer) sign(w http.ResponseWriter, r *http.Request, isHash bool) {
	id, err := checkAuth(w, r, srv.AuthTokens)
	if err != nil {
		logError(err)
		return
	}

	data, err := getData(w, r, isHash)
	if err != nil {
		logError(err)
		return
	}

	// create HTTPMessage with individual response channel for each request
	respChan := make(chan HTTPResponse)

	// submit message for singing
	srv.MessageHandler <- HTTPMessage{ID: id, Data: data, Response: respChan}

	// wait for response from ubirch backend to be forwarded
	forwardBackendResponse(w, respChan)
}

func (srv *HTTPServer) signHash(w http.ResponseWriter, r *http.Request) {
	err := assertContentType(w, r, BinType)
	if err != nil {
		logError(err)
		return
	}

	srv.sign(w, r, true)
}

func (srv *HTTPServer) signJSON(w http.ResponseWriter, r *http.Request) {
	err := assertContentType(w, r, JSONType)
	if err != nil {
		logError(err)
		return
	}

	srv.sign(w, r, false)
}

func (srv *HTTPServer) Serve(ctx context.Context, wg *sync.WaitGroup, TLS bool, certFile string, keyFile string) {
	router := chi.NewMux()
	router.Post(fmt.Sprintf("/{%s}", UUIDKey), srv.signJSON)
	router.Post(fmt.Sprintf("/{%s}/hash", UUIDKey), srv.signHash)

	server := &http.Server{
		Addr:         ":8080",
		Handler:      router,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  75 * time.Second,
	}

	go func() {
		<-ctx.Done()
		log.Printf("shutting down http server")
		server.SetKeepAlivesEnabled(false) // disallow clients to create new long-running conns
		if err := server.Shutdown(ctx); err != nil {
			log.Printf("Failed to gracefully shutdown server: %s", err)
		}
	}()

	go func() {
		defer wg.Done()

		log.Printf("starting HTTP service (TCP port %s)", server.Addr)
		var err error
		if TLS {
			log.Printf("TLS enabled")
			err = server.ListenAndServeTLS(certFile, keyFile)
		} else {
			err = server.ListenAndServe()
		}
		if err != nil && err != http.ErrServerClosed {
			log.Fatalf("error starting HTTP service: %v", err)
		}
	}()
}
