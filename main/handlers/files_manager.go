package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/ubirch/ubirch-client-go/main/ent"
	h "github.com/ubirch/ubirch-client-go/main/handlers/httphelper"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/google/uuid"
	"github.com/ubirch/ubirch-protocol-go/ubirch/v2"

	log "github.com/sirupsen/logrus"
)

const (
	keyFileName      = "keys.json"
	signatureDirName = "signatures"
	authTokenDirName = "tokens"
	filePerm         = 0644
	dirPerm          = 0755

	contextFileName_Legacy = "protocol.json" // TODO: DEPRECATED
)

type FileManager struct {
	keyFile           string
	signatureDir      string
	authTokenDir      string
	identities        []ent.Identity
	EncryptedKeystore *ubirch.EncryptedKeystore
	keystoreMutex     *sync.RWMutex
}

func (f *FileManager) SendChainedUpp(ctx context.Context, msg h.HTTPRequest, s *Signer) (*h.HTTPResponse, error) {
	panic("not implemented")
}

func (f *FileManager) Exists(uid uuid.UUID) (bool, error) {
	f.keystoreMutex.RLock()
	defer f.keystoreMutex.RUnlock()

	_, err := f.EncryptedKeystore.GetPrivateKey(uid)
	if err != nil {
		return false, nil
	}
	return true, nil
}

func (f *FileManager) FetchIdentity(uid uuid.UUID) (*ent.Identity, error) {
	panic("implement me")
}

func (f *FileManager) StoreIdentity(ctx context.Context, identity ent.Identity, handler *IdentityHandler) error {
	panic("implement me")
}

// Ensure FileManager implements the ContextManager interface
var _ ContextManager = (*FileManager)(nil)

func NewFileManager(configDir string, secret []byte) (*FileManager, error) {
	f := &FileManager{
		keyFile:           filepath.Join(configDir, keyFileName),
		signatureDir:      filepath.Join(configDir, signatureDirName),
		authTokenDir:      filepath.Join(configDir, authTokenDirName),
		EncryptedKeystore: ubirch.NewEncryptedKeystore(secret),
		keystoreMutex:     &sync.RWMutex{},
	}

	err := initDirectories([]string{f.signatureDir, f.authTokenDir})
	if err != nil {
		return nil, err
	}

	log.Info("protocol context will be stored in local file system")
	log.Debugf(" - keystore file: %s", f.keyFile)
	log.Debugf(" - signature dir: %s", f.signatureDir)
	log.Debugf(" - token dir: %s", f.authTokenDir)

	err = f.portLegacyProtocolCtxFile(configDir)
	if err != nil {
		return nil, err
	}

	err = f.portLegacyKeystoreFile()
	if err != nil {
		return nil, err
	}

	err = f.loadKeys()
	if err != nil {
		return nil, err
	}

	ids, err := f.EncryptedKeystore.GetIDs()
	if err != nil {
		return nil, err
	}
	log.Infof("loaded %d existing keys from local file system", len(ids))

	return f, nil
}

func (f *FileManager) GetPrivateKey(uid uuid.UUID) ([]byte, error) {
	f.keystoreMutex.RLock()
	defer f.keystoreMutex.RUnlock()

	return f.EncryptedKeystore.GetPrivateKey(uid)
}

func (f *FileManager) SetPrivateKey(uid uuid.UUID, key []byte) error {
	f.keystoreMutex.Lock()
	defer f.keystoreMutex.Unlock()

	return f.EncryptedKeystore.SetPrivateKey(uid, key)
}

func (f *FileManager) GetPublicKey(uid uuid.UUID) ([]byte, error) {
	f.keystoreMutex.RLock()
	defer f.keystoreMutex.RUnlock()

	return f.EncryptedKeystore.GetPublicKey(uid)
}

func (f *FileManager) SetPublicKey(uid uuid.UUID, key []byte) error {
	f.keystoreMutex.Lock()
	defer f.keystoreMutex.Unlock()

	return f.EncryptedKeystore.SetPublicKey(uid, key)
}

func (f *FileManager) GetSignature(uid uuid.UUID) ([]byte, error) {
	return ioutil.ReadFile(f.signatureFile(uid))
}

func (f *FileManager) SetSignature(uid uuid.UUID, signature []byte) error {
	return ioutil.WriteFile(f.signatureFile(uid), signature, filePerm)
}

func (f *FileManager) GetAuthToken(uid uuid.UUID) (string, error) {
	tokenBytes, err := ioutil.ReadFile(f.authTokenFile(uid))
	if err != nil {
		return "", err
	}

	return string(tokenBytes), nil
}

func (f *FileManager) SetAuthToken(uid uuid.UUID, authToken string) error {
	return ioutil.WriteFile(f.authTokenFile(uid), []byte(authToken), filePerm)
}

func (f *FileManager) Close() error {
	return nil
}

func (f *FileManager) signatureFile(uid uuid.UUID) string {
	signatureFileName := uid.String() + ".bin"
	return filepath.Join(f.signatureDir, signatureFileName)
}

func (f *FileManager) authTokenFile(uid uuid.UUID) string {
	authTokenFileName := uid.String() + ".bin"
	return filepath.Join(f.authTokenDir, authTokenFileName)
}

func (f *FileManager) loadKeys() error {
	return loadFile(f.keyFile, f.EncryptedKeystore.Keystore)
}

func (f *FileManager) persistKeys() error {
	return persistFile(f.keyFile, f.EncryptedKeystore.Keystore)
}

func initDirectories(directories []string) error {
	for _, dir := range directories {
		if _, err := os.Stat(dir); os.IsNotExist(err) {
			err = os.Mkdir(dir, dirPerm)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func loadFile(file string, dest interface{}) error {
	if _, err := os.Stat(file); os.IsNotExist(err) { // if file does not exist yet, return right away
		return nil
	}
	contextBytes, err := ioutil.ReadFile(file)
	if err != nil {
		file = file + ".bck"
		contextBytes, err = ioutil.ReadFile(file)
		if err != nil {
			return err
		}
	}
	err = json.Unmarshal(contextBytes, dest)
	if err != nil {
		if strings.HasSuffix(file, ".bck") {
			return err
		} else {
			return loadFile(file+".bck", dest)
		}
	}
	return nil
}

func persistFile(file string, source interface{}) error {
	if _, err := os.Stat(file); !os.IsNotExist(err) { // if file already exists, create a backup
		err = os.Rename(file, file+".bck")
		if err != nil {
			log.Warnf("unable to create backup file for %s: %v", file, err)
		}
	}
	contextBytes, _ := json.MarshalIndent(source, "", "  ")
	return ioutil.WriteFile(file, contextBytes, filePerm)
}

// this is here only for the purpose of backwards compatibility TODO: DEPRECATE
type legacyCryptoCtx struct {
	Keystore map[string]string
}

type legacyProtocolCtx struct {
	Crypto     legacyCryptoCtx
	Signatures map[uuid.UUID][]byte
}

func (f *FileManager) portLegacyProtocolCtxFile(configDir string) error {
	contextFileLegacy := filepath.Join(configDir, contextFileName_Legacy)

	if _, err := os.Stat(contextFileLegacy); os.IsNotExist(err) { // if file does not exist, return right away
		return nil
	}

	p := &legacyProtocolCtx{
		Crypto:     legacyCryptoCtx{Keystore: map[string]string{}},
		Signatures: map[uuid.UUID][]byte{},
	}

	// read legacy protocol context from persistent storage
	err := loadFile(contextFileLegacy, p)
	if err != nil {
		return fmt.Errorf("unable to load legacy protocol context: %v", err)
	}

	// persist loaded keys to new key storage
	err = persistFile(f.keyFile, p.Crypto.Keystore)
	if err != nil {
		return fmt.Errorf("unable to persist keys: %v", err)
	}

	// persist loaded signatures to new signature storage
	err = f.persistSignatures(p.Signatures)
	if err != nil {
		return fmt.Errorf("unable to persist signatures: %v", err)
	}

	// delete legacy protocol ctx file + bckup
	err = os.Remove(contextFileLegacy)
	if err != nil {
		log.Warnf("unable to delete legacy protocol context file: %v", err)
	}
	err = os.Remove(contextFileLegacy + ".bck")
	if err != nil {
		log.Warnf("unable to delete legacy protocol context backup file: %v", err)
	}

	return nil
}

func (f *FileManager) persistSignatures(signatures map[uuid.UUID][]byte) error {
	for uid, signature := range signatures {

		if len(signature) != 64 {
			return fmt.Errorf("invalid signature length: expected 64, got %d", len(signature))
		}

		err := f.SetSignature(uid, signature)
		if err != nil {
			return err
		}
	}
	return nil
}

func (f *FileManager) portLegacyKeystoreFile() error {
	legacyKeystoreFile := &legacyCryptoCtx{Keystore: map[string]string{}}

	// read legacy protocol context from persistent storage
	err := loadFile(f.keyFile, legacyKeystoreFile)
	if err != nil {
		return fmt.Errorf("unable to load legacy protocol context: %v", err)
	}

	if len(legacyKeystoreFile.Keystore) == 0 {
		return nil
	}

	// persist loaded keys to new key storage
	err = persistFile(f.keyFile, legacyKeystoreFile.Keystore)
	if err != nil {
		return fmt.Errorf("unable to persist keys: %v", err)
	}

	return nil
}
