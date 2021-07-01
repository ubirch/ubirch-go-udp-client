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

package repository

import (
	"context"
	"fmt"
	"sync"

	"github.com/google/uuid"
	"github.com/ubirch/ubirch-client-go/main/adapters/clients"
	"github.com/ubirch/ubirch-client-go/main/adapters/encrypters"
	"github.com/ubirch/ubirch-client-go/main/ent"
	"github.com/ubirch/ubirch-protocol-go/ubirch/v2"
)

type ExtendedProtocol struct {
	ubirch.Protocol
	*clients.Client
	ctxManager   ContextManager
	keyEncrypter *encrypters.KeyEncrypter
	keyDerivator *encrypters.KeyDerivator

	AuthBuffer      map[uuid.UUID]string
	AuthBufferMutex *sync.RWMutex
}

func NewExtendedProtocol(ctxManager ContextManager, secret, salt []byte, client *clients.Client) (*ExtendedProtocol, error) {
	crypto := &ubirch.ECDSACryptoContext{}

	enc, err := encrypters.NewKeyEncrypter(secret, crypto)
	if err != nil {
		return nil, err
	}

	p := &ExtendedProtocol{
		Protocol: ubirch.Protocol{
			Crypto: crypto,
		},
		Client:       client,
		ctxManager:   ctxManager,
		keyEncrypter: enc,
		keyDerivator: encrypters.NewDefaultKeyDerivator(salt),

		AuthBuffer:      map[uuid.UUID]string{},
		AuthBufferMutex: &sync.RWMutex{},
	}

	return p, nil
}

func (p *ExtendedProtocol) StartTransaction(ctx context.Context) (transactionCtx interface{}, err error) {
	return p.ctxManager.StartTransaction(ctx)
}

func (p *ExtendedProtocol) StartTransactionWithLock(ctx context.Context, uid uuid.UUID) (transactionCtx interface{}, err error) {
	return p.ctxManager.StartTransactionWithLock(ctx, uid)
}

func (p *ExtendedProtocol) CloseTransaction(tx interface{}, commit bool) error {
	return p.ctxManager.CloseTransaction(tx, commit)
}

func (p *ExtendedProtocol) Exists(uid uuid.UUID) (bool, error) {
	p.AuthBufferMutex.RLock()
	_, found := p.AuthBuffer[uid]
	p.AuthBufferMutex.RUnlock()

	if found {
		return true, nil
	}
	return p.ctxManager.Exists(uid)
}

func (p *ExtendedProtocol) StoreNewIdentity(tx interface{}, i *ent.Identity) error {
	// check validity of identity attributes
	err := p.checkIdentityAttributes(i)
	if err != nil {
		return err
	}

	// encrypt private key
	i.PrivateKey, err = p.keyEncrypter.Encrypt(i.PrivateKey)
	if err != nil {
		return err
	}

	// store public key raw bytes
	i.PublicKey, err = p.PublicKeyPEMToBytes(i.PublicKey)
	if err != nil {
		return err
	}

	// get a derived key from the auth token
	i.AuthToken = p.keyDerivator.GetDerivedKey(i.AuthToken)

	return p.ctxManager.StoreNewIdentity(tx, i)
}

func (p *ExtendedProtocol) FetchIdentity(tx interface{}, uid uuid.UUID) (*ent.Identity, error) {
	i, err := p.ctxManager.FetchIdentity(tx, uid)
	if err != nil {
		return nil, err
	}

	err = p.checkIdentityAttributes(i)
	if err != nil {
		return nil, err
	}

	// decrypt private key
	i.PrivateKey, err = p.keyEncrypter.Decrypt(i.PrivateKey)
	if err != nil {
		return nil, err
	}

	// return public key in PEM format
	i.PublicKey, err = p.PublicKeyBytesToPEM(i.PublicKey)
	if err != nil {
		return nil, err
	}

	return i, nil
}

// FetchIdentityWithLock starts a transaction with lock and returns the locked identity
func (p *ExtendedProtocol) FetchIdentityWithLock(ctx context.Context, uid uuid.UUID) (transactionCtx interface{}, identity *ent.Identity, err error) {
	transactionCtx, err = p.StartTransactionWithLock(ctx, uid)
	if err != nil {
		return nil, nil, fmt.Errorf("starting transaction with lock failed: %v", err)
	}

	identity, err = p.FetchIdentity(transactionCtx, uid)
	if err != nil {
		return nil, nil, fmt.Errorf("could not fetch identity: %v", err)
	}

	return transactionCtx, identity, nil
}

// SetSignature stores the signature and commits the transaction
func (p *ExtendedProtocol) SetSignature(tx interface{}, uid uuid.UUID, signature []byte) error {
	if len(signature) != p.SignatureLength() {
		return fmt.Errorf("invalid signature length: expected %d, got %d", p.SignatureLength(), len(signature))
	}

	err := p.ctxManager.SetSignature(tx, uid, signature)
	if err != nil {
		return err
	}

	return p.CloseTransaction(tx, Commit)
}

func (p *ExtendedProtocol) SetAuthToken(tx interface{}, uid uuid.UUID, authToken string) error {
	if len(authToken) == 0 {
		return fmt.Errorf("empty auth token")
	}

	derivedKeyFromToken := p.keyDerivator.GetDerivedKey(authToken)

	return p.ctxManager.SetAuthToken(tx, uid, derivedKeyFromToken)
}

func (p *ExtendedProtocol) GetPrivateKey(uid uuid.UUID) ([]byte, error) {
	encryptedPrivateKey, err := p.ctxManager.GetPrivateKey(uid)
	if err != nil {
		return nil, err
	}

	return p.keyEncrypter.Decrypt(encryptedPrivateKey)
}

func (p *ExtendedProtocol) GetPublicKey(uid uuid.UUID) (pubKeyPEM []byte, err error) {
	publicKeyBytes, err := p.ctxManager.GetPublicKey(uid)
	if err != nil {
		return nil, err
	}

	return p.PublicKeyBytesToPEM(publicKeyBytes)
}

func (p *ExtendedProtocol) CheckAuthToken(uid uuid.UUID, authTokenToCheck string) (ok bool, err error) {
	p.AuthBufferMutex.RLock()
	derivedKeyFromToken, found := p.AuthBuffer[uid]
	p.AuthBufferMutex.RUnlock()

	if !found {
		derivedKeyFromToken, err = p.ctxManager.GetAuthToken(uid)
		if err != nil {
			return false, err
		}

		if len(derivedKeyFromToken) == 0 {
			return false, fmt.Errorf("%s: empty auth token", uid)
		}

		p.AuthBufferMutex.Lock()
		p.AuthBuffer[uid] = derivedKeyFromToken
		p.AuthBufferMutex.Unlock()
	}

	return derivedKeyFromToken == p.keyDerivator.GetDerivedKey(authTokenToCheck), nil
}

func (p *ExtendedProtocol) checkIdentityAttributes(i *ent.Identity) error {
	if i.Uid == uuid.Nil {
		return fmt.Errorf("uuid has Nil value: %s", i.Uid)
	}

	if len(i.PrivateKey) == 0 {
		return fmt.Errorf("private key is empty")
	}

	if len(i.PublicKey) == 0 {
		return fmt.Errorf("public key is empty")
	}

	if len(i.Signature) != p.SignatureLength() {
		return fmt.Errorf("invalid signature length: expected %d, got %d", p.SignatureLength(), len(i.Signature))
	}

	if len(i.AuthToken) == 0 {
		return fmt.Errorf("%s: empty auth token", i.Uid)
	}

	return nil
}
