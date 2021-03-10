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
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/google/uuid"
	"net/http"

	"github.com/ubirch/ubirch-protocol-go/ubirch/v2"

	log "github.com/sirupsen/logrus"
)

const lenRequestID = 16

var (
	env              string
	authServiceURL   string
	signedUPPHeader  = []byte{0x95, 0x22}
	chainedUPPHeader = []byte{0x96, 0x23}
)

type signingResponse struct {
	Error     string       `json:"error,omitempty"`
	Hash      []byte       `json:"hash,omitempty"`
	UPP       []byte       `json:"upp,omitempty"`
	Response  HTTPResponse `json:"response,omitempty"`
	RequestID string       `json:"requestID,omitempty"`
}

// handle incoming messages, create, sign and send a ubirch protocol packet (UPP) to the ubirch backend
func signer(ctx context.Context, msgHandler chan HTTPMessage, p *ExtendedProtocol, conf Config) error {
	env = conf.Env
	authServiceURL = conf.Niomon

	for {
		select {
		case msg := <-msgHandler:
			name := msg.ID.String()

			// buffer last previous signature to be able to reset it in case sending UPP to backend fails
			prevSign, found := p.Signatures[msg.ID]
			if !found {
				prevSign = make([]byte, 64)
			}

			resp := handleSigningRequest(p, name, msg.Hash[:], msg.Auth)
			msg.Response <- resp
			if httpFailed(resp.StatusCode) {
				log.Errorf("%s: %s", name, string(resp.Content))

				// reset previous signature in protocol context to ensure intact chain
				p.Signatures[msg.ID] = prevSign
			} else {
				// persist last signature after UPP was successfully received in ubirch backend
				err := p.PersistContext()
				if err != nil {
					msg.Response <- errorResponse(http.StatusInternalServerError, "")
					return fmt.Errorf("unable to persist last signature: %v [\"%s\": \"%s\"]",
						err, name, base64.StdEncoding.EncodeToString(p.Signatures[msg.ID]))
				}
			}

		case <-ctx.Done():
			log.Println("finishing signer")
			return nil
		}
	}
}

func handleSigningRequest(p *ExtendedProtocol, name string, hash []byte, auth []byte) HTTPResponse {
	log.Infof("%s: hash: %s", name, base64.StdEncoding.EncodeToString(hash))

	// send a UPP containing the hash to UBIRCH authentication service
	requestUPPStruct, backendResp, err := anchorHash(p, name, hash, auth)
	if err != nil {
		return errorResponse(http.StatusInternalServerError, err.Error())
	}

	// verify validity of the backend response
	responseUPPStruct, err := verifyBackendResponse(p, requestUPPStruct, backendResp)
	if err != nil {
		return getSigningResponse(http.StatusBadGateway, requestUPPStruct, backendResp, "n/a", err.Error())
	}

	// get request ID from backend response
	requestID, err := getRequestID(responseUPPStruct)
	if err != nil {
		log.Warnf("could not get request ID from backend response: %v", err)
	} else {
		log.Infof("%s: request ID: %s", name, requestID)
	}

	return getSigningResponse(backendResp.StatusCode, requestUPPStruct, backendResp, requestID, "")
}

func anchorHash(p *ExtendedProtocol, name string, hash []byte, auth []byte) (ubirch.UPP, HTTPResponse, error) {
	// create a chained UPP
	uppBytes, err := p.SignHash(name, hash, ubirch.Chained)
	if err != nil {
		return nil, HTTPResponse{}, fmt.Errorf("could not create UBIRCH Protocol Package: %v", err)
	}
	log.Debugf("%s: UPP: %s", name, hex.EncodeToString(uppBytes))

	uppStruct, err := ubirch.Decode(uppBytes)
	if err != nil {
		return nil, HTTPResponse{}, fmt.Errorf("could not decode created UBIRCH Protocol Package: %v", err)
	}

	// send UPP to ubirch backend
	resp, err := post(authServiceURL, uppBytes, niomonHeaders(name, auth))
	if err != nil {
		return nil, HTTPResponse{}, fmt.Errorf("sending request to UBIRCH Authentication Service failed: %v", err)
	}
	log.Debugf("%s: backend response: (%d) %s", name, resp.StatusCode, hex.EncodeToString(resp.Content))

	return uppStruct, resp, nil
}

func niomonHeaders(name string, auth []byte) map[string]string {
	return map[string]string{
		"x-ubirch-hardware-id": name,
		"x-ubirch-auth-type":   "ubirch",
		"x-ubirch-credential":  base64.StdEncoding.EncodeToString(auth),
	}
}

func verifyBackendResponse(p *ExtendedProtocol, requUPPStruct ubirch.UPP, backendResp HTTPResponse) (ubirch.UPP, error) {
	// check if backend response is a UPP or something else, like an error message string, for example "Timeout"
	if !hasUPPHeaders(backendResp.Content) {
		return nil, fmt.Errorf("unexpected backend response: (%d) %q", backendResp.StatusCode, backendResp.Content)
	}

	// verify backend response signature
	if verified, err := p.Verify(env, backendResp.Content); !verified {
		if err != nil {
			log.Errorf("could not verify backend response signature: %v", err)
		}
		return nil, fmt.Errorf("backend response signature verification failed")
	}

	// decode the backend response UPP
	respUPPStruct, err := ubirch.Decode(backendResp.Content)
	if err != nil {
		log.Errorf("decoding backend response failed: %v", err)
		return nil, fmt.Errorf("invalid backend response UPP")
	}

	// verify that backend response previous signature matches signature of request UPP
	if httpSuccess(backendResp.StatusCode) {
		if chainOK, err := ubirch.CheckChainLink(requUPPStruct, respUPPStruct); !chainOK {
			if err != nil {
				log.Errorf("could not verify backend response chain: %v", err)
			}
			return nil, fmt.Errorf("backend response chain check failed")
		}
	}

	return respUPPStruct, nil
}

func hasUPPHeaders(data []byte) bool {
	return bytes.HasPrefix(data, signedUPPHeader) || bytes.HasPrefix(data, chainedUPPHeader)
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
		Headers:    http.Header{"Content-Type": {"text/plain; charset=utf-8"}},
		Content:    []byte(message),
	}
}

func getSigningResponse(respCode int, uppStruct ubirch.UPP, backendResp HTTPResponse, requestID string, errMsg string) HTTPResponse {
	uppBytes, err := ubirch.Encode(uppStruct)
	if err != nil {
		log.Warnf("error decoding UPP: %v", err)
	}

	signingResp, err := json.Marshal(signingResponse{
		Hash:      uppStruct.GetPayload(),
		UPP:       uppBytes,
		Response:  backendResp,
		RequestID: requestID,
		Error:     errMsg,
	})
	if err != nil {
		log.Warnf("error serializing signing response: %v", err)
	}

	return HTTPResponse{
		StatusCode: respCode,
		Headers:    http.Header{"Content-Type": {"application/json"}},
		Content:    signingResp,
	}
}
