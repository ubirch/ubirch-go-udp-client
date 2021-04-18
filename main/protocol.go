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
	"fmt"

	"github.com/google/uuid"
	"github.com/ubirch/ubirch-protocol-go/ubirch/v2"
)

type ExtendedProtocol struct {
	ubirch.Protocol
	ContextManager
}

type Identity struct {
	uid        uuid.UUID
	privateKey []byte
	publicKey  []byte
	signature  []byte
	authToken  string
}

type ContextManager interface {
	StartTransaction(uid uuid.UUID) error
	EndTransaction(uid uuid.UUID, success bool) error

	GetPrivateKey(uid uuid.UUID) ([]byte, error)
	SetPrivateKey(uid uuid.UUID, key []byte) error

	GetPublicKey(uid uuid.UUID) ([]byte, error)
	SetPublicKey(uid uuid.UUID, key []byte) error

	GetSignature(uid uuid.UUID) ([]byte, error)
	SetSignature(uid uuid.UUID, signature []byte) error

	GetAuthToken(uid uuid.UUID) (string, error)
	SetAuthToken(uid uuid.UUID, authToken string) error

	Close() error
}

func NewExtendedProtocol(cryptoCtx ubirch.Crypto, ctxManager ContextManager) (*ExtendedProtocol, error) {
	p := &ExtendedProtocol{
		Protocol: ubirch.Protocol{
			Crypto: cryptoCtx,
		},
		ContextManager: ctxManager,
	}

	return p, nil
}

func (p *ExtendedProtocol) GetPrivateKey(uid uuid.UUID) ([]byte, error) {
	// todo sanity checks
	return p.ContextManager.GetPrivateKey(uid)
}
func (p *ExtendedProtocol) SetPrivateKey(uid uuid.UUID, key []byte) error {
	// todo sanity checks
	return p.ContextManager.SetPrivateKey(uid, key)
}

func (p *ExtendedProtocol) GetPublicKey(uid uuid.UUID) ([]byte, error) {
	// todo sanity checks
	return p.ContextManager.GetPublicKey(uid)

}
func (p *ExtendedProtocol) SetPublicKey(uid uuid.UUID, key []byte) error {
	// todo sanity checks
	return p.ContextManager.SetPublicKey(uid, key)
}

func (p *ExtendedProtocol) GetSignature(uid uuid.UUID) ([]byte, error) {
	signature, err := p.ContextManager.GetSignature(uid)
	if err != nil {
		return nil, err
	}

	err = p.checkSignatureLen(signature)
	if err != nil {
		return nil, err
	}

	return signature, nil
}

func (p *ExtendedProtocol) SetSignature(uid uuid.UUID, signature []byte) error {
	err := p.checkSignatureLen(signature)
	if err != nil {
		return err
	}

	return p.ContextManager.SetSignature(uid, signature)
}

func (p *ExtendedProtocol) checkSignatureLen(signature []byte) error {
	if len(signature) != p.SignatureLength() {
		return fmt.Errorf("invalid signature length: expected %d, got %d", p.SignatureLength(), len(signature))
	}
	return nil
}

func (p *ExtendedProtocol) GetAuthToken(uid uuid.UUID) (string, error) {
	authToken, err := p.ContextManager.GetAuthToken(uid)
	if err != nil {
		return "", err
	}

	if len(authToken) == 0 {
		return "", fmt.Errorf("empty auth token")
	}

	return authToken, nil
}

func (p *ExtendedProtocol) SetAuthToken(uid uuid.UUID, authToken string) error {
	if len(authToken) == 0 {
		return fmt.Errorf("empty auth token")
	}

	return p.ContextManager.SetAuthToken(uid, authToken)
}
