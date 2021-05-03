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
	"fmt"
	"github.com/google/uuid"
	"github.com/ubirch/ubirch-client-go/main/config"
	"github.com/ubirch/ubirch-client-go/main/ent"
	h "github.com/ubirch/ubirch-client-go/main/handlers/httphelper"
	"github.com/ubirch/ubirch-protocol-go/ubirch/v2"
)

type ExtendedProtocol struct {
	ubirch.Protocol
	ContextManager
}

type ContextManager interface {
	GetPrivateKey(uid uuid.UUID) ([]byte, error)

	StoreIdentity(ctx context.Context, identity ent.Identity, handler *IdentityHandler) error
	FetchIdentity(uid uuid.UUID) (*ent.Identity, error)

	GetPublicKey(uid uuid.UUID) ([]byte, error)

	SendChainedUpp(ctx context.Context, msg h.HTTPRequest, s *Signer) (*h.HTTPResponse, error)

	GetAuthToken(uid uuid.UUID) (string, error)
}

func GetCtxManager(c config.Config) (ContextManager, error) {
	if c.Dsn.Db != "" && c.Dsn.User != "" {
		return NewSqlDatabaseInfo(c)
	} else {
		return NewFileManager(c.ConfigDir, c.SecretBytes16)
	}
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

func (p *ExtendedProtocol) StoreIdentity(ctx context.Context, id ent.Identity, handler *IdentityHandler) error {
	// check valid attributes
	if len(id.AuthToken) == 0 {
		return fmt.Errorf("%s: empty token", id.Uid)
	}

	err := p.checkSignatureLen(id.Signature)
	if err != nil {
		return fmt.Errorf("%s: %v", id.Uid, err)
	}

	if id.PrivateKey == nil || len(id.PrivateKey) == 0 {
		return fmt.Errorf("private key is empty")
	}

	if id.PublicKey == nil || len(id.PublicKey) == 0 {
		return fmt.Errorf("public key is empty")
	}

	return p.ContextManager.StoreIdentity(ctx, id, handler)
}

func (p *ExtendedProtocol) GetPublicKey(uid uuid.UUID) (pubKeyPEM []byte, err error) {
	return p.ContextManager.GetPublicKey(uid)
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
		return "", fmt.Errorf("%s: empty auth token", uid)
	}

	return authToken, nil
}
