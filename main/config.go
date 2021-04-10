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

package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"github.com/kelseyhightower/envconfig"

	log "github.com/sirupsen/logrus"
)

const (
	DEV_STAGE  = "dev"
	DEMO_STAGE = "demo"
	PROD_STAGE = "prod"

	defaultKeyURL      = "https://key.%s.ubirch.com/api/keyService/v1/pubkey"
	defaultIdentityURL = "https://identity.%s.ubirch.com/api/certs/v1/csr/register"
	defaultNiomonURL   = "https://niomon.%s.ubirch.com/"
	defaultVerifyURL   = "https://verify.%s.ubirch.com/api/upp/verify"

	authEnv  = "UBIRCH_AUTH_MAP" // {UUID: [key, token]} TODO: DEPRECATED
	authFile = "auth.json"       // {UUID: [key, token]} TODO: DEPRECATED

	identitiesFile = "identities.json" // [{ "uuid": "<uuid>", "password": "<auth>" }]

	defaultTLSCertFile = "cert.pem"
	defaultTLSKeyFile  = "key.pem"

	defaultReqBufSize = 30
)

var ENV string

// configuration of the client
type Config struct {
	Devices          map[string]string `json:"devices"`           // maps UUIDs to backend auth tokens (mandatory)
	Secret           string            `json:"secret"`            // secret used to encrypt the key store (mandatory)
	Env              string            `json:"env"`               // the ubirch backend environment [dev, demo, prod], defaults to 'prod'
	DSN              string            `json:"DSN"`               // "data source name" for database connection
	StaticKeys       bool              `json:"staticKeys"`        // disable dynamic key generation, defaults to 'false'
	Keys             map[string]string `json:"keys"`              // maps UUIDs to injected private keys
	CSR_Country      string            `json:"CSR_country"`       // subject country for public key Certificate Signing Requests
	CSR_Organization string            `json:"CSR_organization"`  // subject organization for public key Certificate Signing Requests
	TCP_addr         string            `json:"TCP_addr"`          // the TCP address for the server to listen on, in the form "host:port", defaults to ":8080"
	TLS              bool              `json:"TLS"`               // enable serving HTTPS endpoints, defaults to 'false'
	TLS_CertFile     string            `json:"TLSCertFile"`       // filename of TLS certificate file name, defaults to "cert.pem"
	TLS_KeyFile      string            `json:"TLSKeyFile"`        // filename of TLS key file name, defaults to "key.pem"
	CORS             bool              `json:"CORS"`              // enable CORS, defaults to 'false'
	CORS_Origins     []string          `json:"CORS_origins"`      // list of allowed origin hosts, defaults to ["*"]
	Debug            bool              `json:"debug"`             // enable extended debug output, defaults to 'false'
	LogTextFormat    bool              `json:"logTextFormat"`     // log in text format for better human readability, default format is JSON
	RequestBufSize   int               `json:"RequestBufferSize"` // number of requests to the client that will be buffered for chaining
	SecretBytes      []byte            // the decoded key store secret (set automatically)
	KeyService       string            // key service URL (set automatically)
	IdentityService  string            // identity service URL (set automatically)
	Niomon           string            // authentication service URL (set automatically)
	VerifyService    string            // verification service URL (set automatically)
	configDir        string            // directory where config and protocol ctx are stored (set automatically)
}

func (c *Config) Load(configDir string, filename string) error {
	c.configDir = configDir

	// assume that we want to load from env instead of config files, if
	// we have the UBIRCH_SECRET env variable set.
	var err error
	if os.Getenv("UBIRCH_SECRET") != "" {
		err = c.loadEnv()
	} else {
		err = c.loadFile(filename)
	}
	if err != nil {
		return err
	}

	c.SecretBytes, err = base64.StdEncoding.DecodeString(c.Secret)
	if err != nil {
		return fmt.Errorf("unable to decode base64 encoded secret (%s): %v", c.Secret, err)
	}

	if c.Debug {
		log.SetLevel(log.DebugLevel) // TODO: make configurable
	}
	if c.LogTextFormat {
		log.SetFormatter(&log.TextFormatter{FullTimestamp: true, TimestampFormat: "2006-01-02 15:04:05.000 -0700"})
	}

	err = c.loadAuthMap() // TODO: DEPRECATED
	if err != nil {
		return err
	}

	err = c.loadIdentitiesFile()
	if err != nil {
		return err
	}

	err = c.checkMandatory()
	if err != nil {
		return err
	}

	// set defaults
	c.setDefaultCSR()
	c.setDefaultTLS()
	c.setDefaultCORS()
	c.setDefaultReqBufSize()
	return c.setDefaultURLs()
}

func (c *Config) GetCtxManager() (ContextManager, error) {
	if c.DSN != "" {
		return nil, fmt.Errorf("database not supported in current client version")
		// FIXME: use the database
		// return NewPostgres(c.DSN)
	} else {
		return NewFileManager(c.configDir)
	}
}

// loadEnv reads the configuration from environment variables
func (c *Config) loadEnv() error {
	log.Infof("loading configuration from environment variables")
	return envconfig.Process("ubirch", c)
}

// LoadFile reads the configuration from a json file
func (c *Config) loadFile(filename string) error {
	configFile := filepath.Join(c.configDir, filename)
	log.Infof("loading configuration from file: %s", configFile)

	fileHandle, err := os.Open(configFile)
	if err != nil {
		return err
	}
	defer fileHandle.Close()

	return json.NewDecoder(fileHandle).Decode(c)
}

func (c *Config) checkMandatory() error {
	if len(c.Devices) == 0 {
		return fmt.Errorf("There are no devices authorized to use this client.\n" +
			"It is mandatory to set at least one device UUID and auth token in the configuration.\n" +
			"For more information take a look at the README under 'Configuration'.")
	} else {
		log.Infof("%d known UUID(s)", len(c.Devices))
		for name := range c.Devices {
			log.Debugf(" - %s", name)
		}
	}

	if len(c.SecretBytes) != 16 {
		return fmt.Errorf("secret length must be 16 bytes (is %d)", len(c.SecretBytes))
	}

	if len(c.Keys) != 0 {
		log.Infof("%d injected key(s)", len(c.Keys))
	}

	if c.StaticKeys {
		log.Debug("dynamic key generation disabled")
		if len(c.Keys) == 0 {
			return fmt.Errorf("dynamic key generation disabled but no injected signing keys found in configuration")
		}
	} else {
		log.Debug("dynamic key generation enabled")
	}

	return nil
}

func (c *Config) setDefaultCSR() {
	if c.CSR_Country == "" {
		c.CSR_Country = "DE"
	}
	log.Debugf("CSR Subject Country: %s", c.CSR_Country)

	if c.CSR_Organization == "" {
		c.CSR_Organization = "ubirch GmbH"
	}
	log.Debugf("CSR Subject Organization: %s", c.CSR_Organization)
}

func (c *Config) setDefaultTLS() {
	if c.TCP_addr == "" {
		c.TCP_addr = ":8080"
	}
	log.Debugf("TCP address: %s", c.TCP_addr)

	if c.TLS {
		log.Debug("TLS enabled")

		if c.TLS_CertFile == "" {
			c.TLS_CertFile = defaultTLSCertFile
		}
		c.TLS_CertFile = filepath.Join(c.configDir, c.TLS_CertFile)
		log.Debugf(" - Cert: %s", c.TLS_CertFile)

		if c.TLS_KeyFile == "" {
			c.TLS_KeyFile = defaultTLSKeyFile
		}
		c.TLS_KeyFile = filepath.Join(c.configDir, c.TLS_KeyFile)
		log.Debugf(" -  Key: %s", c.TLS_KeyFile)
	}
}

func (c *Config) setDefaultCORS() {
	if c.CORS {
		log.Debug("CORS enabled")

		if c.CORS_Origins == nil {
			c.CORS_Origins = []string{"*"} // allow all origins
		}
		log.Debugf(" - Allowed Origins: %v", c.CORS_Origins)
	}
}

func (c *Config) setDefaultReqBufSize() {
	if c.RequestBufSize == 0 {
		c.RequestBufSize = defaultReqBufSize
	}
	log.Debugf("request buffer size: %d", c.RequestBufSize)
}

func (c *Config) setDefaultURLs() error {
	if c.Env == "" {
		c.Env = PROD_STAGE
	}

	// assert Env variable value is a valid UBIRCH backend environment
	if !(c.Env == DEV_STAGE || c.Env == DEMO_STAGE || c.Env == PROD_STAGE) {
		return fmt.Errorf("invalid UBIRCH backend environment: \"%s\"", c.Env)
	}

	ENV = c.Env
	log.Infof("UBIRCH backend environment: %s", c.Env)

	if c.KeyService == "" {
		c.KeyService = fmt.Sprintf(defaultKeyURL, c.Env)
	} else {
		c.KeyService = strings.TrimSuffix(c.KeyService, "/mpack")
	}

	if c.IdentityService == "" {
		c.IdentityService = fmt.Sprintf(defaultIdentityURL, c.Env)
	}

	if c.Niomon == "" {
		c.Niomon = fmt.Sprintf(defaultNiomonURL, c.Env)
	}

	if c.VerifyService == "" {
		c.VerifyService = fmt.Sprintf(defaultVerifyURL, c.Env)
	}

	log.Debugf(" - Key Service: %s", c.KeyService)
	log.Debugf(" - Identity Service: %s", c.IdentityService)
	log.Debugf(" - Authentication Service: %s", c.Niomon)
	log.Debugf(" - Verification Service: %s", c.VerifyService)

	return nil
}

// loadIdentitiesFile loads device identities from the identities JSON file.
// Returns without error if file does not exist.
func (c *Config) loadIdentitiesFile() error {
	// if file does not exist, return right away
	if _, err := os.Stat(identitiesFile); os.IsNotExist(err) {
		return nil
	}

	fileHandle, err := os.Open(filepath.Join(c.configDir, identitiesFile))
	if err != nil {
		return err
	}
	defer fileHandle.Close()

	var identities []map[string]string
	err = json.NewDecoder(fileHandle).Decode(&identities)
	if err != nil {
		return err
	}

	if c.Devices == nil {
		c.Devices = make(map[string]string, len(identities))
	}

	for _, identity := range identities {
		c.Devices[identity["uuid"]] = identity["password"]
	}

	return nil
}

// TODO: DEPRECATED
//  loadAuthMap loads the auth map from the environment >> legacy <<
//  Returns without error if neither env variable nor file exists.
func (c *Config) loadAuthMap() error {
	var err error
	var authMapBytes []byte

	authMap := os.Getenv(authEnv)
	if authMap != "" {
		authMapBytes = []byte(authMap)
	} else {
		// if file does not exist, return
		if _, err := os.Stat(authFile); os.IsNotExist(err) {
			return nil
		}
		authMapBytes, err = ioutil.ReadFile(filepath.Join(c.configDir, authFile))
		if err != nil {
			return err
		}
	}

	buffer := make(map[string][]string)
	err = json.Unmarshal(authMapBytes, &buffer)
	if err != nil {
		return err
	}

	if c.Keys == nil {
		c.Keys = make(map[string]string, len(buffer))
	}

	if c.Devices == nil {
		c.Devices = make(map[string]string, len(buffer))
	}

	for k, v := range buffer {
		c.Keys[k] = v[0]
		c.Devices[k] = v[1]
	}

	return nil
}
