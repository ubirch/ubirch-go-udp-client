package repository

import (
	"context"
	"database/sql"
	"encoding/base64"
	"fmt"
	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"
	"github.com/ubirch/ubirch-client-go/main/config"
	"github.com/ubirch/ubirch-client-go/main/ent"
	"github.com/ubirch/ubirch-client-go/main/vars"
	"os"
	"strings"
)

const (
	VersionTableName = "version"
	MigrationID      = "dbMigration"
	MigrationVersion = "2.0"
)

const (
	PostgresIdentity = iota
	PostgresVersion
)

type Migration struct {
	Id               string
	MigrationVersion string
}

var create = map[int]string{
	PostgresIdentity: "CREATE TABLE IF NOT EXISTS %s(" +
		"uid VARCHAR(255) NOT NULL PRIMARY KEY, " +
		"private_key BYTEA NOT NULL, " +
		"public_key BYTEA NOT NULL, " +
		"signature BYTEA NOT NULL, " +
		"auth_token VARCHAR(255) NOT NULL);",
	PostgresVersion: "CREATE TABLE IF NOT EXISTS %s(" +
		"id VARCHAR(255) NOT NULL PRIMARY KEY, " +
		"migration_version VARCHAR(255) NOT NULL);",
}

func CreateTable(tableType int, tableName string) string {
	return fmt.Sprintf(create[tableType], tableName)
}

func Migrate(c config.Config) error {
	dm, err := NewSqlDatabaseInfo(c.PostgresDSN, vars.PostgreSqlIdentityTableName)
	if err != nil {
		return err
	}

	v, err := getVersion(dm)
	if err != nil {
		return err
	}
	if v.MigrationVersion == MigrationVersion {
		log.Infof("database migration version already up to date")
		return nil
	}
	log.Debugf("database migration version: %s / application migration version: %s", v.MigrationVersion, MigrationVersion)

	p, err := NewExtendedProtocol(dm, c.SecretBytes32, c.SaltBytes, nil)
	if err != nil {
		return err
	}

	if strings.HasPrefix(v.MigrationVersion, "0.") {
		// migrate from file based context
		identitiesToPort, err := getAllIdentitiesFromLegacyCtx(c)
		if err != nil {
			return err
		}

		err = migrateIdentities(p, identitiesToPort)
		if err != nil {
			return err
		}

		log.Infof("successfully migrated file based context into database")
	}

	if strings.HasPrefix(v.MigrationVersion, "1.") {
		err = encryptTokens(dm, p)
		if err != nil {
			return err
		}

		log.Infof("successfully encrypted auth tokens in database")
	}

	v.MigrationVersion = MigrationVersion
	return updateVersion(dm, v)
}

func getAllIdentitiesFromLegacyCtx(c config.Config) ([]ent.Identity, error) {
	log.Infof("getting existing identities from file system")

	secret16Bytes, err := base64.StdEncoding.DecodeString(c.Secret16Base64)
	if err != nil {
		return nil, fmt.Errorf("unable to decode base64 encoded secret for legacy key store decoding (%s): %v", c.Secret16Base64, err)
	}
	if len(secret16Bytes) != 16 {
		return nil, fmt.Errorf("invalid secret for legacy key store decoding: secret length must be 16 bytes (is %d)", len(secret16Bytes))
	}

	fileManager, err := NewFileManager(c.ConfigDir, secret16Bytes)
	if err != nil {
		return nil, err
	}

	uids, err := fileManager.EncryptedKeystore.GetIDs()
	if err != nil {
		return nil, err
	}

	var allIdentities []ent.Identity

	for _, uid := range uids {

		i := ent.Identity{
			Uid: uid,
		}

		i.PrivateKey, err = fileManager.GetPrivateKey(uid)
		if err != nil {
			return nil, fmt.Errorf("%s: %v", uid, err)
		}

		i.PublicKey, err = fileManager.GetPublicKey(uid)
		if err != nil {
			return nil, fmt.Errorf("%s: %v", uid, err)
		}

		i.Signature, err = fileManager.GetSignature(uid)
		if err != nil {
			if os.IsNotExist(err) { // if file does not exist -> create genesis signature
				i.Signature = make([]byte, 64)
			} else { // file exists but something went wrong
				return nil, fmt.Errorf("%s: %v", uid, err)
			}
		}

		i.AuthToken, err = fileManager.GetAuthToken(uid)
		if err != nil {
			if os.IsNotExist(err) { // if file does not exist -> get auth token from config
				i.AuthToken = c.Devices[uid.String()]
			} else { // file exists but something went wrong
				return nil, fmt.Errorf("%s: %v", uid, err)
			}
		}

		allIdentities = append(allIdentities, i)
	}

	return allIdentities, nil
}

func migrateIdentities(p *ExtendedProtocol, identities []ent.Identity) error {
	log.Infof("starting migration...")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tx, err := p.StartTransaction(ctx)
	if err != nil {
		return err
	}

	for i, id := range identities {
		log.Infof("%4d: %s", i+1, id.Uid)

		err = p.StoreNewIdentity(tx, &id)
		if err != nil {
			if err == ErrExists {
				log.Warn(err)
			} else {
				return err
			}
		}
	}

	return p.CloseTransaction(tx, Commit)
}

func encryptTokens(dm *DatabaseManager, p *ExtendedProtocol) error {
	query := fmt.Sprintf("SELECT uid, auth_token FROM %s", dm.tableName)

	rows, err := dm.db.Query(query)
	if err != nil {
		return err
	}
	defer rows.Close()

	var (
		uid  uuid.UUID
		auth string
	)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tx, err := p.StartTransaction(ctx)
	if err != nil {
		return err
	}

	for rows.Next() {
		err = rows.Scan(&uid, &auth)
		if err != nil {
			return err
		}

		err = p.SetAuthToken(tx, uid, auth)
		if err != nil {
			return err
		}
	}
	if rows.Err() != nil {
		return rows.Err()
	}

	return p.CloseTransaction(tx, Commit)
}

func getVersion(dm *DatabaseManager) (*Migration, error) {
	_, err := dm.db.Exec(CreateTable(PostgresVersion, vars.PostgreSqlVersionTableName))
	if err != nil {
		return nil, err
	}

	version := &Migration{
		Id: MigrationID,
	}

	query := fmt.Sprintf("SELECT migration_version FROM %s WHERE id = $1", VersionTableName)

	err = dm.db.QueryRow(query, version.Id).
		Scan(&version.MigrationVersion)
	if err != nil {
		if err == sql.ErrNoRows {
			version.MigrationVersion = "0.0"
			return version, createVersionEntry(dm, version)
		} else {
			return nil, err
		}
	}
	return version, nil
}

func updateVersion(dm *DatabaseManager, v *Migration) error {
	query := fmt.Sprintf("UPDATE %s SET migration_version = $1 WHERE id = $2;", VersionTableName)
	_, err := dm.db.Exec(query,
		v.MigrationVersion, &v.Id)
	if err != nil {
		return err
	}
	return nil
}

func createVersionEntry(dm *DatabaseManager, v *Migration) error {
	query := fmt.Sprintf("INSERT INTO %s (id, migration_version) VALUES ($1, $2);", VersionTableName)
	_, err := dm.db.Exec(query,
		&v.Id, v.MigrationVersion)
	if err != nil {
		return err
	}
	return nil
}
