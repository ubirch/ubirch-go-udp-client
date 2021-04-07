// Copyright (c) 2019-2020 ubirch GmbH
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/google/uuid"
	"github.com/ubirch/ubirch-protocol-go/ubirch/v2"

	log "github.com/sirupsen/logrus"

	"time"
)

type operation string

const (
	anchorHash  operation = "anchor"
	disableHash operation = "disable"
	enableHash  operation = "enable"
	deleteHash  operation = "delete"

	lenRequestID = 16
)

var hintLookup = map[operation]ubirch.Hint{
	anchorHash:  ubirch.Binary,
	disableHash: ubirch.Disable,
	enableHash:  ubirch.Enable,
	deleteHash:  ubirch.Delete,
}

type signingResponse struct {
	Error     string       `json:"error,omitempty"`
	Operation operation    `json:"operation,omitempty"`
	Hash      []byte       `json:"hash,omitempty"`
	UPP       []byte       `json:"upp,omitempty"`
	Response  HTTPResponse `json:"response,omitempty"`
	RequestID string       `json:"requestID,omitempty"`
}

type Signer struct {
	protocol       *ExtendedProtocol
	env            string
	authServiceURL string
}

// non-blocking sending to response channel. returns right away if there is no receiver
func (msg HTTPRequest) respond(resp HTTPResponse) {
	select {
	case msg.Response <- resp:
	default:
		log.Warnf("%s: request has been processed, but response could not be sent: (%d) %s",
			msg.ID, resp.StatusCode, string(resp.Content))
	}
}

// handle incoming messages, create, sign and send a chained ubirch protocol packet (UPP) to the ubirch backend
func (s *Signer) chainer(jobs <-chan HTTPRequest, elapsed chan<- time.Duration) error {
	log.Debugf("starting chainer")
	defer close(elapsed)

	for msg := range jobs {
		// the message might have waited in the channel for a while
		// check if the context is expired or canceled by now
		if msg.RequestCtx.Err() != nil {
			continue
		}

		log.Infof("%s: anchor hash [chained]: %s", msg.ID, base64.StdEncoding.EncodeToString(msg.Hash[:]))

		start := time.Now()

		upp, err := s.getChainedUPP(msg.ID, msg.Hash[:])
		if err != nil {
			log.Errorf("%s: could not create UBIRCH Protocol Package: %v", msg.ID, err)
			msg.respond(errorResponse(http.StatusInternalServerError, ""))
			continue // todo should this be fatal?
		}

		resp := s.sendUPP(msg, upp)

		msg.respond(resp)

		elapsed <- time.Since(start)

		// persist last signature only if UPP was successfully received by ubirch backend
		if httpSuccess(resp.StatusCode) {
			signature := upp[len(upp)-s.protocol.SignatureLength():]
			err := s.protocol.PersistSignature(msg.ID, signature)
			if err != nil {
				return fmt.Errorf("unable to persist last signature: %v [\"%s\": \"%s\"]",
					err, msg.ID, base64.StdEncoding.EncodeToString(signature))
			}
		}
	}

	log.Debugf("shutting down chainer")
	return nil
}

func (s *Signer) updateHash(msg HTTPRequest) HTTPResponse {
	log.Infof("%s: %s hash: %s", msg.ID, msg.Operation, base64.StdEncoding.EncodeToString(msg.Hash[:]))

	upp, err := s.getSignedUPP(msg.ID, msg.Hash[:], msg.Operation)
	if err != nil {
		log.Errorf("%s: could not create UBIRCH Protocol Package: %v", msg.ID, err)
		return errorResponse(http.StatusInternalServerError, "")
	}

	return s.sendUPP(msg, upp)
}

func (s *Signer) getChainedUPP(id uuid.UUID, hash []byte) ([]byte, error) {
	prevSignature, err := s.protocol.LoadSignature(id)
	if err != nil {
		return nil, err
	}

	return s.protocol.Sign(
		&ubirch.ChainedUPP{
			Version:       ubirch.Chained,
			Uuid:          id,
			PrevSignature: prevSignature,
			Hint:          ubirch.Binary,
			Payload:       hash,
		},
	)
}

func (s *Signer) getSignedUPP(id uuid.UUID, hash []byte, op operation) ([]byte, error) {
	hint, found := hintLookup[op]
	if !found {
		return nil, fmt.Errorf("%s: invalid operation: \"%s\"", id, op)
	}

	return s.protocol.Sign(
		&ubirch.SignedUPP{
			Version: ubirch.Signed,
			Uuid:    id,
			Hint:    hint,
			Payload: hash,
		},
	)
}

func (s *Signer) sendUPP(msg HTTPRequest, upp []byte) HTTPResponse {
	log.Debugf("%s: UPP: %s", msg.ID, hex.EncodeToString(upp))

	// send UPP to ubirch backend
	backendResp, err := post(s.authServiceURL, upp, ubirchHeader(msg.ID, msg.Auth))
	if err != nil {
		log.Errorf("%s: sending request to UBIRCH Authentication Service failed: %v", msg.ID, err)
		return errorResponse(http.StatusInternalServerError, "")
	}
	log.Debugf("%s: backend response: (%d) %s", msg.ID, backendResp.StatusCode, hex.EncodeToString(backendResp.Content))

	// decode the backend response UPP and get request ID
	var requestID string
	responseUPPStruct, err := ubirch.Decode(backendResp.Content)
	if err != nil {
		log.Warnf("decoding backend response failed: %v, backend response: (%d) %q",
			err, backendResp.StatusCode, backendResp.Content)
	} else {
		requestID, err = getRequestID(responseUPPStruct)
		if err != nil {
			log.Warnf("could not get request ID from backend response: %v", err)
		} else {
			log.Infof("%s: request ID: %s", msg.ID, requestID)
		}
	}

	return getSigningResponse(backendResp.StatusCode, msg, upp, backendResp, requestID, "")
}

func getRequestID(respUPP ubirch.UPP) (string, error) {
	respPayload := respUPP.GetPayload()
	if len(respPayload) < lenRequestID {
		return "n/a", fmt.Errorf("response payload does not contain request ID: %q", respPayload)
	}
	requestID, err := uuid.FromBytes(respPayload[:lenRequestID])
	if err != nil {
		return "n/a", err
	}
	return requestID.String(), nil
}

func errorResponse(code int, message string) HTTPResponse {
	if message == "" {
		message = http.StatusText(code)
	}
	return HTTPResponse{
		StatusCode: code,
		Header:     http.Header{"Content-Type": {"text/plain; charset=utf-8"}},
		Content:    []byte(message),
	}
}

func getSigningResponse(respCode int, msg HTTPRequest, upp []byte, backendResp HTTPResponse, requestID string, errMsg string) HTTPResponse {
	signingResp, err := json.Marshal(signingResponse{
		Hash:      msg.Hash[:],
		UPP:       upp,
		Response:  backendResp,
		RequestID: requestID,
		Operation: msg.Operation,
		Error:     errMsg,
	})
	if err != nil {
		log.Warnf("error serializing signing response: %v", err)
	}

	if httpFailed(respCode) {
		log.Errorf("%s: request failed: (%d) %s", msg.ID, respCode, string(signingResp))
	}

	return HTTPResponse{
		StatusCode: respCode,
		Header:     http.Header{"Content-Type": {"application/json"}},
		Content:    signingResp,
	}
}
