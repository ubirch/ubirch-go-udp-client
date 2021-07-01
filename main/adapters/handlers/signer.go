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

package handlers

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os"

	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/ubirch/ubirch-client-go/main/adapters/repository"
	"github.com/ubirch/ubirch-client-go/main/ent"
	"github.com/ubirch/ubirch-protocol-go/ubirch/v2"

	log "github.com/sirupsen/logrus"
	h "github.com/ubirch/ubirch-client-go/main/adapters/httphelper"
	p "github.com/ubirch/ubirch-client-go/main/prometheus"
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
	Error     string         `json:"error,omitempty"`
	Hash      []byte         `json:"hash,omitempty"`
	UPP       []byte         `json:"upp,omitempty"`
	Response  h.HTTPResponse `json:"response,omitempty"`
	RequestID string         `json:"requestID,omitempty"`
}

type Signer struct {
	*repository.ExtendedProtocol
}

// handle incoming messages, create, sign and send a chained ubirch protocol packet (UPP) to the ubirch backend
func (s *Signer) chain(msg HTTPRequest, tx interface{}, identity *ent.Identity) h.HTTPResponse {
	log.Infof("%s: anchor hash [chained]: %s", msg.ID, base64.StdEncoding.EncodeToString(msg.Hash[:]))

	timer := prometheus.NewTimer(p.SignatureCreationDuration)
	uppBytes, err := s.getChainedUPP(msg.ID, msg.Hash, identity.PrivateKey, identity.Signature)
	timer.ObserveDuration()
	if err != nil {
		log.Errorf("%s: could not create chained UPP: %v", msg.ID, err)
		return errorResponse(http.StatusInternalServerError, "")
	}
	log.Debugf("%s: chained UPP: %x", msg.ID, uppBytes)

	resp := s.sendUPP(msg, uppBytes)

	// persist last signature only if UPP was successfully received by ubirch backend
	if h.HttpSuccess(resp.StatusCode) {
		signature := uppBytes[len(uppBytes)-s.Protocol.SignatureLength():]

		err = s.SetSignature(tx, msg.ID, signature)
		if err != nil {
			// this usually happens, if the request context was cancelled because the client already left (timeout or cancel)
			log.Errorf("%s: storing signature failed: %v", msg.ID, err)
			log.Warnf("%s: request has been processed, but response could not be sent: (%d) %s",
				msg.ID, resp.StatusCode, string(resp.Content))
			return errorResponse(http.StatusInternalServerError, "")
		}

		p.SignatureCreationCounter.Inc()
	}

	return resp
}

func (s *Signer) Sign(msg HTTPRequest, op operation) h.HTTPResponse {
	log.Infof("%s: %s hash: %s", msg.ID, op, base64.StdEncoding.EncodeToString(msg.Hash[:]))

	privateKeyPEM, err := s.GetPrivateKey(msg.ID)
	if err != nil {
		log.Errorf("%s: could not fetch private Key for UUID: %v", msg.ID, err)
		return errorResponse(http.StatusInternalServerError, "")
	}

	uppBytes, err := s.getSignedUPP(msg.ID, msg.Hash, privateKeyPEM, op)
	if err != nil {
		log.Errorf("%s: could not create signed UPP: %v", msg.ID, err)
		return errorResponse(http.StatusInternalServerError, "")
	}
	log.Debugf("%s: signed UPP: %x", msg.ID, uppBytes)

	return s.sendUPP(msg, uppBytes)
}

func (s *Signer) getChainedUPP(id uuid.UUID, hash [32]byte, privateKeyPEM, prevSignature []byte) ([]byte, error) {
	return s.Protocol.Sign(
		privateKeyPEM,
		&ubirch.ChainedUPP{
			Version:       ubirch.Chained,
			Uuid:          id,
			PrevSignature: prevSignature,
			Hint:          ubirch.Binary,
			Payload:       hash[:],
		})
}

func (s *Signer) getSignedUPP(id uuid.UUID, hash [32]byte, privateKeyPEM []byte, op operation) ([]byte, error) {
	hint, found := hintLookup[op]
	if !found {
		return nil, fmt.Errorf("%s: invalid operation: \"%s\"", id, op)
	}

	return s.Protocol.Sign(
		privateKeyPEM,
		&ubirch.SignedUPP{
			Version: ubirch.Signed,
			Uuid:    id,
			Hint:    hint,
			Payload: hash[:],
		})
}

func (s *Signer) sendUPP(msg HTTPRequest, upp []byte) h.HTTPResponse {
	// send UPP to ubirch backend
	timer := prometheus.NewTimer(p.UpstreamResponseDuration)
	backendResp, err := s.SendToAuthService(msg.ID, msg.Auth, upp)
	timer.ObserveDuration()
	if err != nil {
		if os.IsTimeout(err) {
			log.Errorf("%s: request to UBIRCH Authentication Service timed out after %s: %v", msg.ID, h.BackendRequestTimeout.String(), err)
			return errorResponse(http.StatusGatewayTimeout, "")
		} else {
			log.Errorf("%s: sending request to UBIRCH Authentication Service failed: %v", msg.ID, err)
			return errorResponse(http.StatusInternalServerError, "")
		}
	}
	log.Debugf("%s: backend response: (%d) %x", msg.ID, backendResp.StatusCode, backendResp.Content)

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

func errorResponse(code int, message string) h.HTTPResponse {
	if message == "" {
		message = http.StatusText(code)
	}
	return h.HTTPResponse{
		StatusCode: code,
		Header:     http.Header{"Content-Type": {"text/plain; charset=utf-8"}},
		Content:    []byte(message),
	}
}

func getSigningResponse(respCode int, msg HTTPRequest, upp []byte, backendResp h.HTTPResponse, requestID string, errMsg string) h.HTTPResponse {
	signingResp, err := json.Marshal(signingResponse{
		Hash:      msg.Hash[:],
		UPP:       upp,
		Response:  backendResp,
		RequestID: requestID,
		Error:     errMsg,
	})
	if err != nil {
		log.Warnf("error serializing signing response: %v", err)
	}

	if h.HttpFailed(respCode) {
		log.Errorf("%s: request failed: (%d) %s", msg.ID, respCode, string(signingResp))
	}

	return h.HTTPResponse{
		StatusCode: respCode,
		Header:     http.Header{"Content-Type": {"application/json"}},
		Content:    signingResp,
	}
}
