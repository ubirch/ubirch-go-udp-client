package init

import (
	"fmt"
	log "github.com/sirupsen/logrus"
	"github.com/ubirch/ubirch-client-go/main/config"
	"github.com/ubirch/ubirch-client-go/main/ent"
	"github.com/ubirch/ubirch-client-go/main/handlers"
	"github.com/ubirch/ubirch-client-go/main/keystr"
	"github.com/ubirch/ubirch-client-go/main/vars"
	"os"
)

const (
	Postgres = iota
	//MySQL
	//SQLite
)

var CREATE = map[int]string{
	Postgres: "CREATE TABLE " + vars.PostgreSqlTableName + "(" +
		"uid VARCHAR(255) NOT NULL PRIMARY KEY, " +
		"private_key BYTEA NOT NULL, " +
		"public_key BYTEA NOT NULL, " +
		"signature BYTEA NOT NULL, " +
		"auth_token VARCHAR(255) NOT NULL);",

	//MySQL:    "CREATE TABLE identity (id INT, datetime TIMESTAMP)",
	//SQLite:   "CREATE TABLE identity (id INTEGER, datetime TEXT)",
}

type Table struct {
	exists bool
}

func Migrate(c config.Config) error {
	identitiesToPort, err := getAllIdentitiesFromLegacyCtx(c)
	if err != nil {
		return err
	}

	dbManager, err := handlers.NewSqlDatabaseInfo(c)
	if err != nil {
		return err
	}

	err = checkForTable(dbManager)
	if err != nil {
		return err
	}

	return migrateIdentities(c, dbManager, identitiesToPort)
}

func getAllIdentitiesFromLegacyCtx(c config.Config) ([]ent.Identity, error) {
	fileManager, err := handlers.NewFileManager(c.ConfigDir, c.SecretBytes16)
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

		allIdentities = append(allIdentities, i)
	}

	return allIdentities, nil
}

// TODO: check if there is not an more elegant way of checking for tables
func checkForTable(dm *handlers.DatabaseManager) error {

	var table Table
	query := fmt.Sprintf("SELECT to_regclass('%s') IS NOT NULL", vars.PostgreSqlTableName)

	if err := dm.Db.QueryRow(query).Scan(&table.exists); err != nil {
		return fmt.Errorf("scan rows error: %v", err)
	}
	if !table.exists {
		log.Printf("database table %s doesn't exist creating table", vars.PostgreSqlTableName)
		if _, err := dm.Db.Exec(CREATE[Postgres]); err != nil {
			return err
		}
	}
	return nil
}

func migrateIdentities(c config.Config, dm *handlers.DatabaseManager, identities []ent.Identity) error {

	ks, err := keystr.NewEncryptedKeystore(c.SecretBytes32)
	if err != nil {
		return err
	}

	for _, id := range identities {
		encryptedPrivateKey, err := ks.Encrypt(id.PrivateKey)
		if err != nil {
			return err
		}
		_, err = dm.Db.Exec("INSERT INTO identity (uid, private_key, public_key, signature, auth_token) VALUES ($1, $2, $3, $4, $5);",
			&id.Uid, encryptedPrivateKey, &id.PublicKey, &id.Signature, &id.AuthToken)
		if err != nil {
			return err
		}
	}
	return nil
}
