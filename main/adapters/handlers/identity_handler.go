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
	"github.com/ubirch/ubirch-client-go/main/adapters/repository"
	"github.com/ubirch/ubirch-client-go/main/ent"

	log "github.com/sirupsen/logrus"
)

type IdentityHandler struct {
	Protocol            *repository.ExtendedProtocol
	SubjectCountry      string
	SubjectOrganization string
}

func (i *IdentityHandler) InitIdentities(identities map[string]string) error {
	// create and register keys for identities
	log.Debugf("initializing %d identities...", len(identities))
	for name, auth := range identities {
		// make sure identity name is a valid UUID
		uid, err := uuid.Parse(name)
		if err != nil {
			return fmt.Errorf("invalid identity name \"%s\" (not a UUID): %s", name, err)
		}

		// check if identity is already initialized
		exists, err := i.Protocol.Exists(uid)
		if err != nil {
			return fmt.Errorf("can not check existing context for %s: %s", name, err)
		}

		if exists {
			// already initialized
			log.Debugf("%s already initialized (skip)", uid)
			continue
		}

		// make sure identity has an auth token
		if len(auth) == 0 {
			return fmt.Errorf("missing auth token for identity %s", name)
		}

		_, err = i.InitIdentity(uid, auth)
		if err != nil {
			return err
		}
	}

	return nil
}

func (i *IdentityHandler) InitIdentity(uid uuid.UUID, auth string) (csr []byte, err error) {
	log.Infof("initializing new identity %s", uid)

	// generate a new private key
	privKeyPEM, err := i.Protocol.GenerateKey()
	if err != nil {
		return nil, fmt.Errorf("generating new key for UUID %s failed: %v", uid, err)
	}

	pubKeyPEM, err := i.Protocol.GetPublicKeyFromPrivateKey(privKeyPEM)
	if err != nil {
		return nil, err
	}

	newIdentity := &ent.Identity{
		Uid:        uid,
		PrivateKey: privKeyPEM,
		PublicKey:  pubKeyPEM,
		Signature:  make([]byte, i.Protocol.SignatureLength()),
		AuthToken:  auth,
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tx, err := i.Protocol.StartTransaction(ctx)
	if err != nil {
		return nil, err
	}

	err = i.Protocol.StoreNewIdentity(tx, newIdentity)
	if err != nil {
		return nil, err
	}

	// register public key at the ubirch backend
	csr, err = i.registerPublicKey(privKeyPEM, uid, auth)
	if err != nil {
		return nil, err
	}

	return csr, i.Protocol.CloseTransaction(tx, repository.Commit)
}

func (i *IdentityHandler) FetchIdentity(uid uuid.UUID) (*ent.Identity, error) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tx, err := i.Protocol.StartTransaction(ctx)
	if err != nil {
		return nil, err
	}

	return i.Protocol.FetchIdentity(tx, uid)
}

func (i *IdentityHandler) registerPublicKey(privKeyPEM []byte, uid uuid.UUID, auth string) (csr []byte, err error) {
	keyRegistration, err := i.Protocol.GetSignedKeyRegistration(privKeyPEM, uid)
	if err != nil {
		return nil, fmt.Errorf("error creating public key certificate: %v", err)
	}
	log.Debugf("%s: key certificate: %s", uid, keyRegistration)

	csr, err = i.Protocol.GetCSR(privKeyPEM, uid, i.SubjectCountry, i.SubjectOrganization)
	if err != nil {
		return nil, fmt.Errorf("creating CSR for UUID %s failed: %v", uid, err)
	}
	log.Debugf("%s: CSR [der]: %x", uid, csr)

	err = i.Protocol.SubmitKeyRegistration(uid, keyRegistration, auth)
	if err != nil {
		return nil, fmt.Errorf("key registration for UUID %s failed: %v", uid, err)
	}

	go i.submitCSROrLogError(uid, csr)

	return csr, nil
}

func (i *IdentityHandler) submitCSROrLogError(uid uuid.UUID, csr []byte) {
	err := i.Protocol.SubmitCSR(uid, csr)
	if err != nil {
		log.Errorf("submitting CSR for UUID %s failed: %v", uid, err)
	}
}
