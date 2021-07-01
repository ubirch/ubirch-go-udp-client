package repository

import (
	"context"
	"encoding/base64"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/ubirch/ubirch-client-go/main/adapters/encrypters"
	"github.com/ubirch/ubirch-client-go/main/ent"

	log "github.com/sirupsen/logrus"
)

var (
	saltBase64 = "Vc5UxiZbtzvS+XY7thLauvyH6cIyVK6SNAceIDzYpqM="
	auth       = "password123"
	notAuth    = "!password123"
)

func TestProtocol_CheckAuthToken(t *testing.T) {
	salt, _ := base64.StdEncoding.DecodeString(saltBase64)

	p := &ExtendedProtocol{
		ctxManager:   &mockCtxMngr{},
		keyDerivator: encrypters.NewDefaultKeyDerivator(salt),

		AuthBuffer:      map[uuid.UUID]string{},
		AuthBufferMutex: &sync.RWMutex{},
	}

	err := p.SetAuthToken(nil, uuid.Nil, auth)
	if err != nil {
		t.Fatal(err)
	}

	ok, err := p.CheckAuthToken(uuid.Nil, auth)
	if err != nil {
		t.Fatal(err)
	}

	if !ok {
		log.Error("check of correct auth failed")
	}

	ok, err = p.CheckAuthToken(uuid.Nil, notAuth)
	if err != nil {
		t.Fatal(err)
	}

	if ok {
		log.Error("check of incorrect auth succeeded")
	}
}

type mockCtxMngr struct {
	auth string
}

func (t *mockCtxMngr) SetAuthToken(transactionCtx interface{}, uid uuid.UUID, authToken string) error {
	t.auth = authToken
	return nil
}

func (t *mockCtxMngr) GetAuthToken(uid uuid.UUID) (string, error) {
	return t.auth, nil
}

func (m *mockCtxMngr) StartTransaction(ctx context.Context) (transactionCtx interface{}, err error) {
	panic("implement me")
}

func (m *mockCtxMngr) StartTransactionWithLock(ctx context.Context, uid uuid.UUID) (transactionCtx interface{}, err error) {
	panic("implement me")
}

func (m *mockCtxMngr) CloseTransaction(transactionCtx interface{}, commit bool) error {
	panic("implement me")
}

func (m *mockCtxMngr) Exists(uid uuid.UUID) (bool, error) {
	panic("implement me")
}

func (m *mockCtxMngr) StoreNewIdentity(transactionCtx interface{}, identity *ent.Identity) error {
	panic("implement me")
}

func (m *mockCtxMngr) FetchIdentity(transactionCtx interface{}, uid uuid.UUID) (*ent.Identity, error) {
	panic("implement me")
}

func (m *mockCtxMngr) SetSignature(transactionCtx interface{}, uid uuid.UUID, signature []byte) error {
	panic("implement me")
}

func (m *mockCtxMngr) GetPrivateKey(uid uuid.UUID) ([]byte, error) {
	panic("implement me")
}

func (m *mockCtxMngr) GetPublicKey(uid uuid.UUID) ([]byte, error) {
	panic("implement me")
}

var _ ContextManager = (*mockCtxMngr)(nil)
