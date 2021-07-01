package repository

import (
	"context"
	"errors"
	"fmt"
	"github.com/google/uuid"
	"github.com/ubirch/ubirch-client-go/main/config"
	"github.com/ubirch/ubirch-client-go/main/ent"
	"github.com/ubirch/ubirch-client-go/main/vars"
)

const (
	Commit   = true
	Rollback = false
)

var (
	ErrExists = errors.New("entry already exists")
)

type ContextManager interface {
	StartTransaction(ctx context.Context) (transactionCtx interface{}, err error)
	StartTransactionWithLock(ctx context.Context, uid uuid.UUID) (transactionCtx interface{}, err error)
	CloseTransaction(transactionCtx interface{}, commit bool) error

	Exists(uid uuid.UUID) (bool, error)

	StoreNewIdentity(transactionCtx interface{}, identity *ent.Identity) error
	FetchIdentity(transactionCtx interface{}, uid uuid.UUID) (*ent.Identity, error)

	SetSignature(transactionCtx interface{}, uid uuid.UUID, signature []byte) error
	SetAuthToken(transactionCtx interface{}, uid uuid.UUID, authToken string) error

	GetPrivateKey(uid uuid.UUID) ([]byte, error)
	GetPublicKey(uid uuid.UUID) ([]byte, error)
	GetAuthToken(uid uuid.UUID) (string, error)
}

func GetCtxManager(c config.Config) (ContextManager, error) {
	if c.PostgresDSN != "" {
		return NewSqlDatabaseInfo(c.PostgresDSN, vars.PostgreSqlIdentityTableName)
	} else {
		return nil, fmt.Errorf("file-based context management is not supported in the current version. " +
			"Please set a postgres DSN in the configuration and conntect to a database or downgrade to a version < 2.0.0")
	}
}
