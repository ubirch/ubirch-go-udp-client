/*
 * Copyright (c) 2019 ubirch GmbH
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package main

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/ubirch/ubirch-protocol-go/ubirch/v2"

	log "github.com/sirupsen/logrus"
)

var (
	verifyServiceURL              string
	keyServiceURL                 string
	verifyFromKnownIdentitiesOnly bool
)

type verification struct {
	UPP     []byte `json:"upp"`
	Prev    []byte `json:"prev"`
	Anchors []byte `json:"anchors"`
}

type verificationResponse struct {
	Error  string `json:"error,omitempty"`
	Hash   []byte `json:"hash,omitempty"`
	UPP    []byte `json:"upp,omitempty"`
	UUID   string `json:"uuid,omitempty"`
	PubKey []byte `json:"pubKey,omitempty"`
}

// verifier retrieves corresponding UPP for a given hash from the ubirch backend and verifies the validity of its signature
func verifier(ctx context.Context, msgHandler chan HTTPMessage, p *ExtendedProtocol, conf Config) error {
	verifyServiceURL = conf.VerifyService
	keyServiceURL = conf.KeyService
	verifyFromKnownIdentitiesOnly = true // todo add to config

	for {
		select {
		case msg := <-msgHandler:

			resp := handleVerificationRequest(p, msg.Hash[:])
			msg.Response <- resp
			if httpFailed(resp.StatusCode) {
				log.Errorf("%s", string(resp.Content))
			}

		case <-ctx.Done():
			log.Println("finishing verifier")
			return nil
		}
	}
}

func handleVerificationRequest(p *ExtendedProtocol, hash []byte) HTTPResponse {
	log.Infof("verifying hash %s", base64.StdEncoding.EncodeToString(hash))

	// retrieve certificate for hash from the ubirch backend
	code, upp, err := loadUPP(hash)
	if err != nil {
		return errorResponse(code, err.Error())
	}
	log.Debugf("retrieved UPP %s", hex.EncodeToString(upp))

	// verify validity of the retrieved UPP locally
	name, pkey, err := verifyUPP(p, upp)
	if err != nil {
		return getVerificationResponse(http.StatusUnprocessableEntity, hash, upp, name, pkey, err.Error())
	}
	log.Debugf("verified UPP from identity %s using public key %s", name, base64.StdEncoding.EncodeToString(pkey))

	return getVerificationResponse(http.StatusOK, hash, upp, name, pkey, "")
}

// loadUPP retrieves the UPP which contains a given hash from the ubirch backend
func loadUPP(hash []byte) (int, []byte, error) {
	var resp *http.Response
	var err error
	hashBase64String := base64.StdEncoding.EncodeToString(hash)

	n := 0
	for stay, timeout := true, time.After(5*time.Second); stay; {
		n++
		select {
		case <-timeout:
			stay = false
		default:
			resp, err = http.Post(verifyServiceURL, "text/plain", strings.NewReader(hashBase64String))
			if err != nil {
				return http.StatusInternalServerError, nil, fmt.Errorf("error sending verification request: %v", err)
			}
			stay = httpFailed(resp.StatusCode)
			if stay {
				_ = resp.Body.Close()
				log.Debugf("Couldn't verify hash yet (%d). Retry... %d", resp.StatusCode, n)
				time.Sleep(time.Second)
			}
		}
	}
	//noinspection GoUnhandledErrorResult
	defer resp.Body.Close()

	if httpFailed(resp.StatusCode) {
		respBodyBytes, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			log.Warnf("unable to decode verification response: %v", err)
		}
		return resp.StatusCode, nil, fmt.Errorf("could not retrieve certificate for hash %s from UBIRCH verification service (%s): - %s - %q", hashBase64String, verifyServiceURL, resp.Status, respBodyBytes)
	}

	vf := verification{}
	err = json.NewDecoder(resp.Body).Decode(&vf)
	if err != nil {
		return http.StatusBadGateway, nil, fmt.Errorf("unable to decode verification response: %v", err)
	}
	return resp.StatusCode, vf.UPP, nil
}

// verifyUPP verifies the signature of UPPs from known identities using their public keys from the local keystore
func verifyUPP(p *ExtendedProtocol, upp []byte) (string, []byte, error) {
	uppStruct, err := ubirch.Decode(upp)
	if err != nil {
		return "", nil, fmt.Errorf("retrieved invalid UPP: %v", err)
	}

	id := uppStruct.GetUuid()
	name := id.String()

	pubkey, err := p.GetPublicKey(name)
	if err != nil {
		if verifyFromKnownIdentitiesOnly {
			return name, nil, fmt.Errorf("retrieved certificate for requested hash is from unknown identity")
		} else {
			log.Warnf("couldn't get public key for identity %s from local context", name)
			pubkey, err = loadPublicKey(p, name, id)
			if err != nil {
				return name, nil, err
			}
		}
	}

	verified, err := p.Verify(name, upp)
	if !verified {
		if err != nil {
			log.Error(err)
		}
		return name, pubkey, fmt.Errorf("signature of retrieved certificate for requested hash could not be verified")
	}

	return name, pubkey, nil
}

// loadPublicKey retrieves the first valid public key associated with an identity from the key service
func loadPublicKey(p *ExtendedProtocol, name string, id uuid.UUID) ([]byte, error) {
	log.Debugf("requesting public key for identity %s from key service (%s)", id.String(), keyServiceURL)

	keys, err := requestPublicKeys(keyServiceURL, id)
	if err != nil {
		return nil, err
	}

	if len(keys) < 1 {
		return nil, fmt.Errorf("no public key for identity %s registered at key service (%s)", id.String(), keyServiceURL)
	} else if len(keys) > 1 {
		log.Warnf("several public keys registered for identity %s", id.String())
	}

	log.Printf("retrieved public key for identity %s: %s", keys[0].PubKeyInfo.HwDeviceId, keys[0].PubKeyInfo.PubKey)

	pubkey, err := base64.StdEncoding.DecodeString(keys[0].PubKeyInfo.PubKey)
	if err != nil {
		return nil, fmt.Errorf("error decoding retrieved public key: %v", err)
	}

	// inject new public key into protocol context for verification
	err = p.SetPublicKey(name, id, pubkey)
	if err != nil {
		return nil, fmt.Errorf("unable to set retrieved public key for verification: %v", err)
	}

	err = p.PersistContext()
	if err != nil {
		log.Errorf("unable to persist retrieved public key for UUID %s: %v", name, err)
	}

	return pubkey, nil
}

func getVerificationResponse(respCode int, hash []byte, upp []byte, name string, pkey []byte, errMsg string) HTTPResponse {
	verificationResp, err := json.Marshal(verificationResponse{
		Hash:   hash,
		UPP:    upp,
		UUID:   name,
		PubKey: pkey,
		Error:  errMsg,
	})
	if err != nil {
		log.Warnf("error serializing response: %v", err)
	}

	return HTTPResponse{
		StatusCode: respCode,
		Headers:    http.Header{"Content-Type": {"application/json"}},
		Content:    verificationResp,
	}
}
