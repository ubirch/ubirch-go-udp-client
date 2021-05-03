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
	"database/sql"
	"database/sql/driver"
	"encoding/base64"
	"fmt"
	"github.com/google/uuid"
	"github.com/lib/pq"
	log "github.com/sirupsen/logrus"
	"github.com/ubirch/ubirch-client-go/main/config"
	"github.com/ubirch/ubirch-client-go/main/ent"
	h "github.com/ubirch/ubirch-client-go/main/handlers/httphelper"
	"github.com/ubirch/ubirch-client-go/main/keystr"
	"github.com/ubirch/ubirch-client-go/main/vars"
	// postgres driver is imported for side effects
	_ "github.com/lib/pq"
)

// Database is the interface that defines what methods a database has to
// implement.
type Database interface {
	SetProtocolContext(proto driver.Valuer) error
	GetProtocolContext(proto sql.Scanner) error

	Close() error
}

// Database contains the postgres database connection, and offers methods
// for interacting with the database.
type DatabaseManager struct {
	Options     *sql.TxOptions
	Db          *sql.DB
	Client      Client
	EncKeyStore *keystr.EncryptedKeystore
}

// Ensure Database implements the ContextManager interface
var _ ContextManager = (*DatabaseManager)(nil)

// NewSqlDatabaseInfo takes a database connection string, returns a new initialized
// database.
func NewSqlDatabaseInfo(c config.Config) (*DatabaseManager, error) {
	dataSourceName := fmt.Sprintf("host=%s user=%s password=%s port=%d dbname=%s sslmode=disable",
		c.Dsn.Host, c.Dsn.User, c.Dsn.Password, vars.PostgreSqlPort, c.Dsn.Db)

	pg, err := sql.Open(vars.PostgreSql, dataSourceName)
	if err != nil {
		return nil, err
	}
	//pg.SetMaxOpenConns(100)
	//pg.SetMaxIdleConns(100)
	//pg.SetConnMaxLifetime(5*time.Minute)
	if err = pg.Ping(); err != nil {
		return nil, err
	}

	log.Print("preparing postgres usage")

	keystore, err := keystr.NewEncryptedKeystore(c.SecretBytes32)
	if err != nil {
		return nil, err
	}

	return &DatabaseManager{
		Options: &sql.TxOptions{
			Isolation: sql.LevelReadCommitted,
			ReadOnly:  false,
		},
		Db:          pg,
		EncKeyStore: keystore}, nil
}

func (dm *DatabaseManager) GetPrivateKey(uid uuid.UUID) ([]byte, error) {

	var identity ent.Identity
	if err := dm.Db.QueryRow("SELECT private_key FROM identity WHERE uid = $1", uid.String()).
		Scan(&identity.PrivateKey); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		} else {
			return nil, err
		}
	}
	decryptedPrivateKey, err := dm.EncKeyStore.Decrypt(identity.PrivateKey)
	if err != nil {
		return nil, err
	}
	return decryptedPrivateKey, nil
}

func (dm *DatabaseManager) GetPublicKey(uid uuid.UUID) ([]byte, error) {

	var identity ent.Identity

	err := dm.Db.QueryRow("SELECT public_key FROM identity WHERE uid = $1", uid.String()).
		Scan(&identity.PublicKey)
	if err != nil {
		return nil, err
	}

	return identity.PublicKey, nil
}

func (dm *DatabaseManager) GetAuthToken(uid uuid.UUID) (string, error) {

	var identity ent.Identity

	err := dm.Db.QueryRow("SELECT auth_token FROM identity WHERE uid = $1", uid.String()).
		Scan(&identity.AuthToken)
	if err != nil {
		if err.Error() == pq.ErrorCode("53300").Name() {
			return "", err
		}
		return "", err
	}

	return identity.AuthToken, nil
}

func (dm *DatabaseManager) FetchIdentity(uid uuid.UUID) (*ent.Identity, error) {
	var identity ent.Identity

	err := dm.Db.QueryRow("SELECT * FROM identity WHERE uid = $1", uid.String()).
		Scan(&identity.Uid, &identity.PrivateKey, &identity.PublicKey, &identity.Signature, &identity.AuthToken)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}

	return &identity, nil
}

func (dm *DatabaseManager) StoreIdentity(ctx context.Context, identity ent.Identity, idHandler *IdentityHandler) error {

	parsedUuid, err := uuid.Parse(identity.Uid)
	if err != nil {
		return err
	}

	tx, err := dm.Db.BeginTx(ctx, dm.Options)
	if err != nil {
		return err
	}

	var existingId ent.Identity
	if err = tx.QueryRow("SELECT uid FROM identity WHERE uid = $1 FOR UPDATE", identity.Uid).Scan(&existingId.Uid); err != nil {
		if err == sql.ErrNoRows {
			// there were no rows, but otherwise no error occurred
		} else {
			tx.Rollback()
			return err
		}
	} else {
		tx.Rollback()
		return fmt.Errorf("entry not unique, uuid already exits %s", identity.Uid)
	}

	if err = idHandler.RegisterPublicKey(identity.PrivateKey, parsedUuid, identity.AuthToken); err != nil {
		tx.Rollback()
		return err
	}

	genesisSignature := make([]byte, idHandler.Protocol.SignatureLength())
	encryptedPrivateKey, err := dm.EncKeyStore.Encrypt(identity.PrivateKey)
	if err != nil {
		tx.Rollback()
		return err
	}
	_, err = tx.ExecContext(ctx,
		"INSERT INTO identity (uid, private_key, public_key, signature, auth_token) VALUES ($1, $2, $3, $4, $5);",
		&identity.Uid, encryptedPrivateKey, &identity.PublicKey, &genesisSignature, &identity.AuthToken)
	if err != nil {
		tx.Rollback()
		return err
	}

	return tx.Commit()
}

// handle incoming messages, create, sign and send a chained ubirch protocol packet (UPP) to the ubirch backend
func (dm *DatabaseManager) SendChainedUpp(ctx context.Context, msg h.HTTPRequest, s *Signer) (*h.HTTPResponse, error) {
	log.Infof("%s: anchor hash [chained]: %s", msg.ID, base64.StdEncoding.EncodeToString(msg.Hash[:]))

	tx, err := dm.Db.BeginTx(ctx, dm.Options)
	if err != nil {
		log.Fatal(err)
	}

	var id ent.Identity
	if err = tx.QueryRow("SELECT * FROM identity WHERE uid = $1 FOR NO KEY UPDATE", msg.ID).Scan(
		&id.Uid, &id.PrivateKey, &id.PublicKey, &id.Signature, &id.AuthToken); err != nil {
		tx.Rollback()
		return nil, err
	}

	decryptedPrivateKey, err := dm.EncKeyStore.Decrypt(id.PrivateKey)
	if err != nil {
		tx.Rollback()
		return nil, err
	}

	uppBytes, err := s.GetChainedUPP(msg.ID, msg.Hash, decryptedPrivateKey, id.Signature)
	if err != nil {
		tx.Rollback()
		log.Errorf("%s: could not create chained UPP: %v", msg.ID, err)
		return nil, err
	}
	log.Debugf("%s: chained UPP: %x", msg.ID, uppBytes)

	resp := s.SendUPP(msg, uppBytes)
	// persist last signature only if UPP was successfully received by ubirch backend
	if !HttpSuccess(resp.StatusCode) {
		tx.Rollback()
		log.Errorf("send upp failed: %v", resp.Content)
		return &resp, nil
	}

	signature := uppBytes[len(uppBytes)-s.Protocol.SignatureLength():]

	_, err = tx.ExecContext(ctx,
		"UPDATE identity SET signature = $1 WHERE uid = $2;",
		&signature, &id.Uid)
	if err != nil {
		tx.Rollback()
		return nil, err
	}

	return &resp, tx.Commit()
}
