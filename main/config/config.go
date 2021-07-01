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

package config

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/kelseyhightower/envconfig"

	log "github.com/sirupsen/logrus"
)

const (
	secretLength32 = 32
	minSaltLength  = 16

	DEV_STAGE  = "dev"
	DEMO_STAGE = "demo"
	PROD_STAGE = "prod"

	defaultKeyURL      = "https://identity.%s.ubirch.com/api/keyService/v1/pubkey"
	defaultIdentityURL = "https://identity.%s.ubirch.com/api/certs/v1/csr/register"
	defaultNiomonURL   = "https://niomon.%s.ubirch.com/"
	defaultVerifyURL   = "https://verify.%s.ubirch.com/api/upp/verify"

	identitiesFileName = "identities.json" // [{ "uuid": "<uuid>", "password": "<auth>" }]

	defaultTCPAddr = ":8080"

	defaultTLSCertFile = "cert.pem"
	defaultTLSKeyFile  = "key.pem"
)

var IsDevelopment bool

// configuration of the client
type Config struct {
	Devices          map[string]string `json:"devices"`                              // maps UUIDs to backend auth tokens (mandatory)
	Secret16Base64   string            `json:"secret" envconfig:"secret"`            // 16 bytes secret used to encrypt the key store (mandatory for migration) LEGACY
	Secret32Base64   string            `json:"secret32" envconfig:"secret32"`        // 32 byte secret used to encrypt the key store (mandatory)
	SaltBase64       string            `json:"salt" envconfig:"SALT"`                // salt for Key Derivation Function, should be 16 bytes or longer (mandatory)
	RegisterAuth     string            `json:"registerAuth"`                         // auth token needed for new identity registration
	Env              string            `json:"env"`                                  // the ubirch backend environment [dev, demo, prod], defaults to 'prod'
	PostgresDSN      string            `json:"postgresDSN" envconfig:"POSTGRES_DSN"` // data source name for postgres database
	CSR_Country      string            `json:"CSR_country"`                          // subject country for public key Certificate Signing Requests
	CSR_Organization string            `json:"CSR_organization"`                     // subject organization for public key Certificate Signing Requests
	TCP_addr         string            `json:"TCP_addr"`                             // the TCP address for the server to listen on, in the form "host:port", defaults to ":8080"
	TLS              bool              `json:"TLS"`                                  // enable serving HTTPS endpoints, defaults to 'false'
	TLS_CertFile     string            `json:"TLSCertFile"`                          // filename of TLS certificate file name, defaults to "cert.pem"
	TLS_KeyFile      string            `json:"TLSKeyFile"`                           // filename of TLS key file name, defaults to "key.pem"
	CORS             bool              `json:"CORS"`                                 // enable CORS, defaults to 'false'
	CORS_Origins     []string          `json:"CORS_origins"`                         // list of allowed origin hosts, defaults to ["*"]
	Debug            bool              `json:"debug"`                                // enable extended debug output, defaults to 'false'
	LogTextFormat    bool              `json:"logTextFormat"`                        // log in text format for better human readability, default format is JSON
	SecretBytes32    []byte            // the decoded 32 byte key store secret for database (set automatically)
	SaltBytes        []byte            // the decoded key derivation salt
	KeyService       string            // key service URL (set automatically)
	IdentityService  string            // identity service URL (set automatically)
	Niomon           string            // authentication service URL (set automatically)
	VerifyService    string            // verification service URL (set automatically)
	ConfigDir        string            // directory where config and protocol ctx are stored (set automatically)
}

func (c *Config) Load(configDir, filename string) error {
	c.ConfigDir = configDir

	// assume that we want to load from env instead of config files, if
	// we have the UBIRCH_SECRET env variable set.
	var err error
	if os.Getenv("UBIRCH_SECRET32") != "" {
		err = c.loadEnv()
	} else {
		err = c.loadFile(filename)
	}
	if err != nil {
		return err
	}

	if c.Debug {
		log.SetLevel(log.DebugLevel)
	}

	if c.LogTextFormat {
		log.SetFormatter(&log.TextFormatter{FullTimestamp: true, TimestampFormat: "2006-01-02 15:04:05.000 -0700"})
	}

	c.SecretBytes32, err = base64.StdEncoding.DecodeString(c.Secret32Base64)
	if err != nil {
		return fmt.Errorf("unable to decode base64 encoded secret (%s): %v", c.Secret32Base64, err)
	}

	c.SaltBytes, err = base64.StdEncoding.DecodeString(c.SaltBase64)
	if err != nil {
		return fmt.Errorf("unable to decode base64 encoded salt (%s): %v", c.SaltBase64, err)
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
	return c.setDefaultURLs()
}

// loadEnv reads the configuration from environment variables
func (c *Config) loadEnv() error {
	log.Infof("loading configuration from environment variables")
	return envconfig.Process("ubirch", c)
}

// LoadFile reads the configuration from a json file
func (c *Config) loadFile(filename string) error {
	configFile := filepath.Join(c.ConfigDir, filename)
	log.Infof("loading configuration from file: %s", configFile)

	fileHandle, err := os.Open(configFile)
	if err != nil {
		return err
	}
	defer fileHandle.Close()

	return json.NewDecoder(fileHandle).Decode(c)
}

func (c *Config) checkMandatory() error {
	if len(c.SecretBytes32) != secretLength32 {
		return fmt.Errorf("secret for aes-256 key encryption ('secret32') length must be %d bytes (is %d)", secretLength32, len(c.SecretBytes32))
	}

	if len(c.SaltBytes) < minSaltLength {
		return fmt.Errorf("salt for key derivation ('salt') length must be at least %d bytes (is %d)", minSaltLength, len(c.SaltBytes))
	}

	if len(c.RegisterAuth) == 0 {
		return fmt.Errorf("auth token for identity registration ('registerAuth') wasn't set")
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
		c.TCP_addr = defaultTCPAddr
	}
	log.Debugf("TCP address: %s", c.TCP_addr)

	if c.TLS {
		log.Debug("TLS enabled")

		if c.TLS_CertFile == "" {
			c.TLS_CertFile = defaultTLSCertFile
		}
		c.TLS_CertFile = filepath.Join(c.ConfigDir, c.TLS_CertFile)
		log.Debugf(" - Cert: %s", c.TLS_CertFile)

		if c.TLS_KeyFile == "" {
			c.TLS_KeyFile = defaultTLSKeyFile
		}
		c.TLS_KeyFile = filepath.Join(c.ConfigDir, c.TLS_KeyFile)
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

func (c *Config) setDefaultURLs() error {
	if c.Env == "" {
		c.Env = PROD_STAGE
	}

	// set flag for non-production environments
	if c.Env == DEV_STAGE || c.Env == DEMO_STAGE {
		IsDevelopment = true
	}

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

	log.Infof("UBIRCH backend environment: %s", c.Env)
	log.Debugf(" - Key Service:            %s", c.KeyService)
	log.Debugf(" - Identity Service:       %s", c.IdentityService)
	log.Debugf(" - Authentication Service: %s", c.Niomon)
	log.Debugf(" - Verification Service:   %s", c.VerifyService)

	return nil
}

// loadIdentitiesFile loads device identities from the identities JSON file.
// Returns without error if file does not exist.
func (c *Config) loadIdentitiesFile() error {
	identitiesFile := filepath.Join(c.ConfigDir, identitiesFileName)

	// if file does not exist, return right away
	if _, err := os.Stat(identitiesFile); os.IsNotExist(err) {
		return nil
	}

	fileHandle, err := os.Open(identitiesFile)
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
