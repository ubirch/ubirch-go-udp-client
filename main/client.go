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
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"

	"github.com/google/uuid"
)

type KeyRegistration struct {
	Algorithm      string `json:"algorithm"`
	Created        string `json:"created"`
	HwDeviceId     string `json:"hwDeviceId"`
	PubKey         string `json:"pubKey"`
	PubKeyId       string `json:"pubKeyId"`
	ValidNotAfter  string `json:"validNotAfter"`
	ValidNotBefore string `json:"validNotBefore"`
}

type SignedKeyRegistration struct {
	PubKeyInfo KeyRegistration `json:"pubKeyInfo"`
	Signature  string          `json:"signature"`
}

// getSignedCertificate creates a self-signed JSON key certificate
// to be sent to the identity service for public key registration
func getSignedCertificate(p *ExtendedProtocol, uid uuid.UUID, pubKey []byte) ([]byte, error) {
	const timeFormat = "2006-01-02T15:04:05.000Z"

	// put it all together
	now := time.Now().UTC()
	keyRegistration := KeyRegistration{
		Algorithm:      "ecdsa-p256v1",
		Created:        now.Format(timeFormat),
		HwDeviceId:     uid.String(),
		PubKey:         base64.StdEncoding.EncodeToString(pubKey),
		PubKeyId:       base64.StdEncoding.EncodeToString(pubKey),
		ValidNotAfter:  now.Add(10 * 365 * 24 * time.Hour).Format(timeFormat), // valid for 10 years
		ValidNotBefore: now.Format(timeFormat),
	}

	// create string representation and sign it
	jsonKeyReg, err := json.Marshal(keyRegistration)
	if err != nil {
		return nil, err
	}

	signature, err := p.Crypto.Sign(uid, jsonKeyReg)
	if err != nil {
		return nil, err
	}

	// fill the certificate
	cert := SignedKeyRegistration{
		PubKeyInfo: keyRegistration,
		Signature:  base64.StdEncoding.EncodeToString(signature),
	}

	return json.Marshal(cert)
}

// post submits a message to a backend service
// returns the response status code, body and headers and encountered errors
func post(url string, data []byte, headers map[string]string) (HTTPResponse, error) {
	client := &http.Client{Timeout: 60 * time.Second}

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(data))
	if err != nil {
		return HTTPResponse{}, fmt.Errorf("can't make new post request: %v", err)
	}

	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := client.Do(req)
	if err != nil {
		return HTTPResponse{}, err
	}

	//noinspection GoUnhandledErrorResult
	defer resp.Body.Close()

	respBodyBytes, err := ioutil.ReadAll(resp.Body)
	return HTTPResponse{
		StatusCode: resp.StatusCode,
		Headers:    resp.Header,
		Content:    respBodyBytes,
	}, err
}

// requestPublicKeys requests a devices public keys at the identity service
// returns a list of the retrieved public key certificates
func requestPublicKeys(keyService string, id uuid.UUID) ([]SignedKeyRegistration, error) {
	url := keyService + "/current/hardwareId/" + id.String()
	resp, err := http.Get(url)
	if err != nil {
		return nil, fmt.Errorf("unable to retrieve public key info: %v", err)
	}
	//noinspection GoUnhandledErrorResult
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return []SignedKeyRegistration{}, nil
	}

	if httpFailed(resp.StatusCode) {
		respContent, _ := ioutil.ReadAll(resp.Body)
		return nil, fmt.Errorf("retrieving public key info from %s failed: (%s) %s", url, resp.Status, string(respContent))
	}

	respBodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("unable to read response body: %v", err)
	}

	var keys []SignedKeyRegistration
	err = json.Unmarshal(respBodyBytes, &keys)
	if err != nil {
		return nil, fmt.Errorf("unable to decode key registration info: %v", err)
	}

	return keys, nil
}

// isKeyRegistered sends a request to the identity service to determine
// if a specified public key is registered for the specified UUID
func isKeyRegistered(keyService string, id uuid.UUID, pubKey []byte) (bool, error) {
	certs, err := requestPublicKeys(keyService, id)
	if err != nil {
		return false, err
	}

	for _, cert := range certs {
		if cert.PubKeyInfo.PubKey == base64.StdEncoding.EncodeToString(pubKey) {
			return true, nil
		}
	}
	return false, nil
}

func httpFailed(StatusCode int) bool {
	return !httpSuccess(StatusCode)
}

func httpSuccess(StatusCode int) bool {
	return StatusCode >= 200 && StatusCode < 300
}
