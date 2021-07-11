package repository

import (
	"context"
	"database/sql"
	"encoding/base64"
	"fmt"
	"os"

	"github.com/ubirch/ubirch-client-go/main/config"
	"github.com/ubirch/ubirch-client-go/main/ent"

	log "github.com/sirupsen/logrus"
)

const (
	PostgresIdentity = iota
	PostgresVersion
	SQLiteIdentity
	SQLiteVersion

	IdentityTableName = "identity"
	VersionTableName  = "version"

	MigrationID      = "dbMigration"
	MigrationVersion = "1.0.1"
)

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

	SQLiteIdentity: "CREATE TABLE IF NOT EXISTS %s(" +
		"uid TEXT NOT NULL PRIMARY KEY, " +
		"private_key BLOB NOT NULL, " +
		"public_key BLOB NOT NULL, " +
		"signature BLOB NOT NULL, " +
		"auth_token TEXT NOT NULL);",
	SQLiteVersion: "CREATE TABLE IF NOT EXISTS %s(" +
		"id TEXT NOT NULL PRIMARY KEY, " +
		"migration_version TEXT NOT NULL);",
}

func (dm *DatabaseManager) CreateTable(tableType int, tableName string) error {
	query := fmt.Sprintf(create[tableType], tableName)

	_, err := dm.db.Exec(query)
	if err != nil {
		return err
	}
	return nil
}

type Migration struct {
	Id               string
	MigrationVersion string
}

func Migrate(c config.Config) error {
	var (
		dm  *DatabaseManager
		err error
	)

	if c.PostgresDSN != "" {
		dm, err = NewSqlDatabaseInfo(PostgreSQL, c.PostgresDSN, IdentityTableName)
	} else if c.SqliteDSN != "" {
		dm, err = NewSqlDatabaseInfo(SQLite, c.SqliteDSN, IdentityTableName)
	} else {
		return fmt.Errorf("missing DSN for postgres or SQLite in configuration")
	}
	if err != nil {
		return err
	}

	current, err := getCurrentVersion(dm)
	if err != nil {
		return err
	}

	if current.MigrationVersion == MigrationVersion {
		log.Infof("database migration version already up to date")
		return nil
	}
	log.Infof("database migration version: %s / application migration version: %s", current.MigrationVersion, MigrationVersion)

	if current.MigrationVersion == "0.0" {
		err = migrateFileToDB(c, dm)
		if err != nil {
			return err
		}

		current.MigrationVersion = MigrationVersion
		err = updateVersion(dm, current)
		if err != nil {
			return err
		}
	}

	if current.MigrationVersion != MigrationVersion {
		return fmt.Errorf("unexpected database migration version: %s", current.MigrationVersion)
	}

	return nil
}

func migrateFileToDB(c config.Config, dm *DatabaseManager) error {
	identitiesToPort, err := getIdentitiesFromFile(c)
	if err != nil {
		return err
	}

	err = storeIdentitiesInDB(c, dm, identitiesToPort)
	if err != nil {
		return err
	}

	log.Infof("successfully migrated file based context into database")
	return nil
}

func getIdentitiesFromFile(c config.Config) ([]ent.Identity, error) {
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

	var identities []ent.Identity

	for _, uid := range uids {

		i := ent.Identity{
			Uid: uid.String(),
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

		identities = append(identities, i)
	}

	log.Infof("found %d identities in file system", len(identities))

	return identities, nil
}

func storeIdentitiesInDB(c config.Config, dm *DatabaseManager, identities []ent.Identity) error {
	log.Infof("starting migration...")

	p, err := NewExtendedProtocol(dm, c.SecretBytes32, nil)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tx, err := dm.StartTransaction(ctx)
	if err != nil {
		return err
	}

	for i, id := range identities {
		log.Infof("%4d: %s", i+1, id.Uid)

		err = p.StoreNewIdentity(tx, &id)
		if err != nil {
			if err == ErrExists {
				log.Warnf("%s: %v", id.Uid, err)
			} else {
				return err
			}
		}
	}

	return dm.CloseTransaction(tx, Commit)
}

func getCurrentVersion(dm *DatabaseManager) (*Migration, error) {
	err := createVersionTable(dm)
	if err != nil {
		return nil, err
	}

	version := &Migration{
		Id: MigrationID,
	}

	var noRows bool

	query := fmt.Sprintf("SELECT migration_version FROM %s WHERE id = $1", VersionTableName)

	err = dm.db.QueryRow(query, version.Id).Scan(&version.MigrationVersion)
	if err != nil {
		if err == sql.ErrNoRows {
			noRows = true
			version.MigrationVersion = "0.0"
		} else {
			return nil, err
		}
	}

	if noRows {
		err = createVersionEntry(dm, version)
		if err != nil {
			return nil, err
		}
	}

	return version, nil
}

func createVersionTable(dm *DatabaseManager) error {
	switch dm.driverName {
	case PostgreSQL:
		return dm.CreateTable(PostgresVersion, VersionTableName)
	case SQLite:
		return dm.CreateTable(SQLiteVersion, VersionTableName)
	default:
		return fmt.Errorf("unsupported SQL driver: %s", dm.driverName)
	}
}

func createVersionEntry(dm *DatabaseManager, v *Migration) error {
	query := fmt.Sprintf("INSERT INTO %s (id, migration_version) VALUES ($1, $2);", VersionTableName)

	_, err := dm.db.Exec(query, &v.Id, v.MigrationVersion)
	if err != nil {
		return err
	}
	return nil
}

func updateVersion(dm *DatabaseManager, v *Migration) error {
	query := fmt.Sprintf("UPDATE %s SET migration_version = $1 WHERE id = $2;", VersionTableName)

	_, err := dm.db.Exec(query, v.MigrationVersion, &v.Id)
	if err != nil {
		return err
	}
	return nil
}
