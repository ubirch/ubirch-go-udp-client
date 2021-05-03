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
	h "github.com/ubirch/ubirch-client-go/main/handlers/httphelper"
	"github.com/ubirch/ubirch-client-go/main/server"
	"net/http"
	"os"

	"github.com/google/uuid"
	"github.com/ubirch/ubirch-protocol-go/ubirch/v2"

	log "github.com/sirupsen/logrus"
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
	Hash      []byte       `json:"hash,omitempty"`
	UPP       []byte       `json:"upp,omitempty"`
	Response  h.HTTPResponse `json:"response,omitempty"`
	RequestID string       `json:"requestID,omitempty"`
}

type Signer struct {
	Protocol *ExtendedProtocol
	Client   *Client
}

func (s *Signer) Sign(msg h.HTTPRequest, op operation) h.HTTPResponse {
	log.Infof("%s: %s hash: %s", msg.ID, op, base64.StdEncoding.EncodeToString(msg.Hash[:]))

	pemPrivateKey, err := s.Protocol.GetPrivateKey(msg.ID)
	if err != nil {
		log.Errorf("%s: could not fetch private Key for UUID: %v", msg.ID, err)
		return h.ErrorResponse(http.StatusInternalServerError, "")
	}

	uppBytes, err := s.getSignedUPP(msg.ID, msg.Hash, pemPrivateKey, op)
	if err != nil {
		log.Errorf("%s: could not create signed UPP: %v", msg.ID, err)
		return h.ErrorResponse(http.StatusInternalServerError, "")
	}
	log.Debugf("%s: signed UPP: %x", msg.ID, uppBytes)

	resp := s.SendUPP(msg, uppBytes)

	return resp
}

func (s *Signer) GetChainedUPP(id uuid.UUID, hash [32]byte, decryptedPrivate, signature []byte) ([]byte, error) {
	return s.Protocol.Sign(
		decryptedPrivate,
		&ubirch.ChainedUPP{
			Version:       ubirch.Chained,
			Uuid:          id,
			PrevSignature: signature,
			Hint:          ubirch.Binary,
			Payload:       hash[:],
		})
}

func (s *Signer) getSignedUPP(id uuid.UUID, hash [32]byte, decryptedPrivate []byte, op operation) ([]byte, error) {

	hint, found := hintLookup[op]
	if !found {
		return nil, fmt.Errorf("%s: invalid operation: \"%s\"", id, op)
	}

	return s.Protocol.Sign(
		decryptedPrivate,
		&ubirch.SignedUPP{
			Version: ubirch.Signed,
			Uuid:    id,
			Hint:    hint,
			Payload: hash[:],
		})
}

func (s *Signer) SendUPP(msg h.HTTPRequest, upp []byte) h.HTTPResponse {
	// send UPP to ubirch backend
	backendResp, err := s.Client.sendToAuthService(msg.ID, msg.Auth, upp)
	if err != nil {
		if os.IsTimeout(err) {
			log.Errorf("%s: request to UBIRCH Authentication Service timed out after %s: %v", msg.ID, server.BackendRequestTimeout.String(), err)
			return h.ErrorResponse(http.StatusGatewayTimeout, "")
		} else {
			log.Errorf("%s: sending request to UBIRCH Authentication Service failed: %v", msg.ID, err)
			return h.ErrorResponse(http.StatusInternalServerError, "")
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

func getSigningResponse(respCode int, msg h.HTTPRequest, upp []byte, backendResp h.HTTPResponse, requestID string, errMsg string) h.HTTPResponse {
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

	if httpFailed(respCode) {
		log.Errorf("%s: request failed: (%d) %s", msg.ID, respCode, string(signingResp))
	}

	return h.HTTPResponse{
		StatusCode: respCode,
		Header:     http.Header{"Content-Type": {"application/json"}},
		Content:    signingResp,
	}
}
