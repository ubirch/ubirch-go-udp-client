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
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/ubirch/ubirch-client-go/main/ent"
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
	Response  HTTPResponse `json:"response,omitempty"`
	RequestID string       `json:"requestID,omitempty"`
}

type Signer struct {
	Protocol *ExtendedProtocol
	Client   *Client
}

func (s *Signer) Sign(msg HTTPRequest, op operation) HTTPResponse {
	log.Infof("%s: %s hash: %s", msg.ID, op, base64.StdEncoding.EncodeToString(msg.Hash[:]))

	uppBytes, err := s.getSignedUPP(msg.ID, msg.Hash, op)
	if err != nil {
		log.Errorf("%s: could not create signed UPP: %v", msg.ID, err)
		return ErrorResponse(http.StatusInternalServerError, "")
	}
	log.Debugf("%s: signed UPP: %x", msg.ID, uppBytes)

	resp := s.SendUPP(msg, uppBytes)

	return resp
}

func (s *Signer) GetChainedUPP(ctx context.Context, id ent.Identity, hash [32]byte, decryptedPrivate []byte) ([]byte, error) {

	parseUuid, err := uuid.Parse(id.Uid)
	if err != nil {
		return nil, err
	}
	return s.Protocol.Sign(
		decryptedPrivate,
		&ubirch.ChainedUPP{
			Version:       ubirch.Chained,
			Uuid:          parseUuid,
			PrevSignature: id.Signature,
			Hint:          ubirch.Binary,
			Payload:       hash[:],
		})
}

func (s *Signer) getSignedUPP(id uuid.UUID, hash [32]byte, op operation) ([]byte, error) {
	privKeyPEM, err := s.Protocol.GetPrivateKey(id)
	if err != nil {
		return nil, err
	}

	hint, found := hintLookup[op]
	if !found {
		return nil, fmt.Errorf("%s: invalid operation: \"%s\"", id, op)
	}

	return s.Protocol.Sign(
		privKeyPEM,
		&ubirch.SignedUPP{
			Version: ubirch.Signed,
			Uuid:    id,
			Hint:    hint,
			Payload: hash[:],
		})
}

func (s *Signer) SendUPP(msg HTTPRequest, upp []byte) HTTPResponse {
	// send UPP to ubirch backend
	backendResp, err := s.Client.sendToAuthService(msg.ID, msg.Auth, upp)
	if err != nil {
		if os.IsTimeout(err) {
			log.Errorf("%s: request to UBIRCH Authentication Service timed out after %s: %v", msg.ID, BackendRequestTimeout.String(), err)
			return ErrorResponse(http.StatusGatewayTimeout, "")
		} else {
			log.Errorf("%s: sending request to UBIRCH Authentication Service failed: %v", msg.ID, err)
			return ErrorResponse(http.StatusInternalServerError, "")
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

func getSigningResponse(respCode int, msg HTTPRequest, upp []byte, backendResp HTTPResponse, requestID string, errMsg string) HTTPResponse {
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

	return HTTPResponse{
		StatusCode: respCode,
		Header:     http.Header{"Content-Type": {"application/json"}},
		Content:    signingResp,
	}
}
