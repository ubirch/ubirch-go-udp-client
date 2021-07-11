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
	"database/sql"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
	"github.com/mattn/go-sqlite3"
	"github.com/ubirch/ubirch-client-go/main/ent"

	log "github.com/sirupsen/logrus"
)

const (
	PostgreSQL string = "postgres"
	SQLite     string = "sqlite3"
)

// DatabaseManager contains the postgres database connection, and offers methods
// for interacting with the database.
type DatabaseManager struct {
	options    *sql.TxOptions
	db         *sql.DB
	driverName string
	tableName  string
}

// Ensure Database implements the ContextManager interface
var _ ContextManager = (*DatabaseManager)(nil)

// NewSqlDatabaseInfo takes a database connection string, returns a new initialized
// database.
func NewSqlDatabaseInfo(driverName, dataSourceName, tableName string) (*DatabaseManager, error) {
	log.Infof("preparing database usage: %s", driverName)

	db, err := sql.Open(driverName, dataSourceName)
	if err != nil {
		return nil, err
	}

	db.SetMaxOpenConns(100) // FIXME
	db.SetMaxIdleConns(70)
	db.SetConnMaxLifetime(10 * time.Minute)
	if err = db.Ping(); err != nil {
		return nil, err
	}

	var isolationLvl sql.IsolationLevel
	var identityTable int

	switch driverName {
	case PostgreSQL:
		isolationLvl = sql.LevelReadCommitted
		identityTable = PostgresIdentity
	case SQLite:
		isolationLvl = sql.LevelSerializable
		identityTable = SQLiteIdentity
	default:
		return nil, fmt.Errorf("unsupported SQL driver: %s", driverName)
	}

	dbManager := &DatabaseManager{
		options: &sql.TxOptions{
			Isolation: isolationLvl,
			ReadOnly:  false,
		},
		db:         db,
		driverName: driverName,
		tableName:  tableName,
	}

	err = dbManager.CreateTable(identityTable, tableName)
	if err != nil {
		return nil, err
	}

	return dbManager, nil
}

func (dm *DatabaseManager) Exists(uid uuid.UUID) (bool, error) {
	var id string

	query := fmt.Sprintf("SELECT uid FROM %s WHERE uid = $1", dm.tableName)

	err := dm.db.QueryRow(query, uid.String()).Scan(&id)
	if err != nil {
		if dm.isConnectionError(err) {
			return dm.Exists(uid)
		}
		if err == sql.ErrNoRows {
			return false, nil
		} else {
			return false, err
		}
	} else {
		return true, nil
	}
}

func (dm *DatabaseManager) GetPrivateKey(uid uuid.UUID) ([]byte, error) {
	var privateKey []byte

	query := fmt.Sprintf("SELECT private_key FROM %s WHERE uid = $1", dm.tableName)

	err := dm.db.QueryRow(query, uid.String()).Scan(&privateKey)
	if err != nil {
		if dm.isConnectionError(err) {
			return dm.GetPrivateKey(uid)
		}
		return nil, err
	}

	return privateKey, nil
}

func (dm *DatabaseManager) GetPublicKey(uid uuid.UUID) ([]byte, error) {
	var publicKey []byte

	query := fmt.Sprintf("SELECT public_key FROM %s WHERE uid = $1", dm.tableName)

	err := dm.db.QueryRow(query, uid.String()).Scan(&publicKey)
	if err != nil {
		if dm.isConnectionError(err) {
			return dm.GetPublicKey(uid)
		}
		return nil, err
	}

	return publicKey, nil
}

func (dm *DatabaseManager) GetAuthToken(uid uuid.UUID) (string, error) {
	var authToken string

	query := fmt.Sprintf("SELECT auth_token FROM %s WHERE uid = $1", dm.tableName)

	err := dm.db.QueryRow(query, uid.String()).Scan(&authToken)
	if err != nil {
		if dm.isConnectionError(err) {
			return dm.GetAuthToken(uid)
		}
		return "", err
	}

	return authToken, nil
}

func (dm *DatabaseManager) StartTransaction(ctx context.Context) (transactionCtx interface{}, err error) {
	tx, err := dm.db.BeginTx(ctx, dm.options)
	if err != nil {
		if dm.isConnectionError(err) {
			return dm.StartTransaction(ctx)
		}
		return nil, err
	}
	return tx, nil
}

// StartTransactionWithLock starts a transaction and acquires a lock on the row with the specified uuid as key.
// Returns error if row does not exist.
func (dm *DatabaseManager) StartTransactionWithLock(ctx context.Context, uid uuid.UUID) (transactionCtx interface{}, err error) {
	tx, err := dm.db.BeginTx(ctx, dm.options)
	if err != nil {
		if dm.isConnectionError(err) {
			return dm.StartTransactionWithLock(ctx, uid)
		}
		return nil, err
	}

	var id string

	query := fmt.Sprintf("SELECT uid FROM %s WHERE uid = $1", dm.tableName)

	if dm.driverName == PostgreSQL {
		query += " FOR UPDATE" // lock row FOR UPDATE
	}

	err = tx.QueryRow(query, uid).Scan(&id)
	if err != nil {
		if dm.isConnectionError(err) {
			return dm.StartTransactionWithLock(ctx, uid)
		}
		return nil, err
	}

	return tx, nil
}

func (dm *DatabaseManager) CloseTransaction(transactionCtx interface{}, commit bool) error {
	tx, ok := transactionCtx.(*sql.Tx)
	if !ok {
		return fmt.Errorf("transactionCtx for database manager is not of expected type *sql.Tx")
	}

	if commit {
		return tx.Commit()
	} else {
		return tx.Rollback()
	}
}

func (dm *DatabaseManager) FetchIdentity(transactionCtx interface{}, uid uuid.UUID) (*ent.Identity, error) {
	tx, ok := transactionCtx.(*sql.Tx)
	if !ok {
		return nil, fmt.Errorf("transactionCtx for database manager is not of expected type *sql.Tx")
	}

	var id ent.Identity

	query := fmt.Sprintf("SELECT * FROM %s WHERE uid = $1", dm.tableName)

	err := tx.QueryRow(query, uid.String()).Scan(&id.Uid, &id.PrivateKey, &id.PublicKey, &id.Signature, &id.AuthToken)
	if err != nil {
		if dm.isConnectionError(err) {
			return dm.FetchIdentity(tx, uid)
		}
		return nil, err
	}

	return &id, nil
}

func (dm *DatabaseManager) SetSignature(transactionCtx interface{}, uid uuid.UUID, signature []byte) error {
	tx, ok := transactionCtx.(*sql.Tx)
	if !ok {
		return fmt.Errorf("transactionCtx for database manager is not of expected type *sql.Tx")
	}

	query := fmt.Sprintf("UPDATE %s SET signature = $1 WHERE uid = $2;", dm.tableName)

	_, err := tx.Exec(query, &signature, uid.String())
	if err != nil {
		if dm.isConnectionError(err) {
			return dm.SetSignature(tx, uid, signature)
		}
		return err
	}

	return nil
}

func (dm *DatabaseManager) StoreNewIdentity(transactionCtx interface{}, identity *ent.Identity) error {
	tx, ok := transactionCtx.(*sql.Tx)
	if !ok {
		return fmt.Errorf("transactionCtx for database manager is not of expected type *sql.Tx")
	}

	// make sure identity does not exist yet
	var id string

	query := fmt.Sprintf("SELECT uid FROM %s WHERE uid = $1", dm.tableName)

	err := tx.QueryRow(query, identity.Uid).Scan(&id)
	if err != nil {
		if dm.isConnectionError(err) {
			return dm.StoreNewIdentity(tx, identity)
		}
		if err == sql.ErrNoRows {
			// there were no rows, but otherwise no error occurred
			return dm.storeIdentity(tx, identity)
		} else {
			return err
		}
	} else {
		return ErrExists
	}
}

func (dm *DatabaseManager) storeIdentity(tx *sql.Tx, identity *ent.Identity) error {
	query := fmt.Sprintf(
		"INSERT INTO %s (uid, private_key, public_key, signature, auth_token) VALUES ($1, $2, $3, $4, $5);",
		dm.tableName)

	_, err := tx.Exec(query, &identity.Uid, &identity.PrivateKey, &identity.PublicKey, &identity.Signature, &identity.AuthToken)
	if err != nil {
		if dm.isConnectionError(err) {
			return dm.storeIdentity(tx, identity)
		}
		return err
	}

	return nil
}

func (dm DatabaseManager) isConnectionError(err error) bool {
	switch dm.driverName {
	case PostgreSQL:
		if err.Error() == pq.ErrorCode("53300").Name() || // "53300": "too_many_connections",
			err.Error() == pq.ErrorCode("53400").Name() { // "53400": "configuration_limit_exceeded",
			time.Sleep(100 * time.Millisecond)
			return true
		}
	case SQLite:
		if err.Error() == sqlite3.ErrBusy.Error() ||
			err.Error() == sqlite3.ErrLocked.Error() {
			time.Sleep(100 * time.Millisecond)
			return true
		}
	}

	return false
}
