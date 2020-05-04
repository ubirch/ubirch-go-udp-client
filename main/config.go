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
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/kelseyhightower/envconfig"
)

const (
	DEV_STAGE  = "dev"
	DEMO_STAGE = "demo"
	PROD_STAGE = "prod"
	KEY_URL    = "https://key.%s.ubirch.com/api/keyService/v1/pubkey"
	NIOMON_URL = "https://niomon.%s.ubirch.com/"
	VERIFY_URL = "https://verify.%s.ubirch.com/api/upp"
)

// configuration of the device
type Config struct {
	Devices       map[string]string `json:"devices"`    // maps UUIDs to backend auth tokens
	Secret        string            `json:"secret"`     // secret used to encrypt the key store
	DSN           string            `json:"DSN"`        // "data source name" for database connection
	StaticUUID    bool              `json:"staticUUID"` // only accept requests from UUIDs with injected signing key. default: false -> dynamic key generation
	Env           string            `json:"env"`        // the ubirch backend environment [dev, demo, prod], defaults to 'prod'
	TLS           bool              `json:"TLS"`        // enable serving HTTPS endpoints, defaults to 'false'
	CertFile      string            `json:"certFile"`   // filename of TLS certificate file, defaults to 'Path + "cert.pem"'
	KeyFile       string            `json:"keyFile"`    // filename of TLS key file, defaults to 'Path + "key.pem"'
	Debug         bool              `json:"debug"`      // enable extended debug output, defaults to 'false'
	KeyService    string            // key service URL (set automatically)
	Niomon        string            // authentication service URL (set automatically)
	VerifyService string            // verification service URL (set automatically)
	SecretBytes   []byte            // the decoded key store secret
}

func (c *Config) Load() error {
	// assume that we want to load from env instead of config files, if
	// we have the UBIRCH_DEVICES env variable set.
	var err error
	if os.Getenv("UBIRCH_DEVICES") != "" {
		err = c.loadEnv()
	} else {
		err = c.loadFile(filepath.Join(Path, ConfigFile))
	}
	if err != nil {
		return err
	}

	c.SecretBytes, err = base64.StdEncoding.DecodeString(c.Secret)
	if err != nil {
		return fmt.Errorf("unable to decode base64 encoded secret (%s): %v", c.Secret, err)
	}

	err = c.checkMandatory()
	if err != nil {
		return err
	}

	c.setDefaultTLS()
	return c.setDefaultURLs()
}

// loadEnv reads the configuration from environment variables
func (c *Config) loadEnv() error {
	log.Println("loading configuration from environment variables")
	return envconfig.Process("ubirch", c)
}

// LoadFile reads the configuration from a json file
func (c *Config) loadFile(filename string) error {
	log.Printf("loading configuration from file (%s)", filename)
	contextBytes, err := ioutil.ReadFile(filename)
	if err != nil {
		return err
	}
	return json.Unmarshal(contextBytes, c)
}

func (c *Config) checkMandatory() error {
	if c.Devices == nil || len(c.Devices) == 0 {
		return fmt.Errorf("There are no devices authorized to use this client.\n" +
			"It is mandatory to set at least one device UUID and auth token in the configuration.\n" +
			"For more information take a look at the README under 'Configuration'.")
	} else {
		log.Printf("loaded %d devices from configuration", len(c.Devices))
	}
	if len(c.SecretBytes) != 16 {
		return fmt.Errorf("secret length must be 16 bytes (is %d)", len(c.SecretBytes))
	}
	return nil
}

func (c *Config) setDefaultTLS() {
	if c.TLS {
		if c.CertFile == "" {
			c.CertFile = filepath.Join(Path, "cert.pem")
		}
		if c.KeyFile == "" {
			c.KeyFile = filepath.Join(Path, "key.pem")
		}
	}
}

func (c *Config) setDefaultURLs() error {
	if c.Env == "" {
		c.Env = PROD_STAGE
	}

	if c.Niomon == "" {
		c.Niomon = fmt.Sprintf(NIOMON_URL, c.Env)
	}

	// now make sure the Env variable has the actual environment value that is used in the URL
	c.Env = strings.Split(c.Niomon, ".")[1]

	// assert Env variable value is a valid UBIRCH backend environment
	if !(c.Env == DEV_STAGE || c.Env == DEMO_STAGE || c.Env == PROD_STAGE) {
		return fmt.Errorf("invalid UBIRCH backend environment: \"%s\"", c.Env)
	}

	log.Printf("using UBIRCH backend \"%s\" environment", c.Env)

	if c.KeyService == "" {
		c.KeyService = fmt.Sprintf(KEY_URL, c.Env)
	} else {
		c.KeyService = strings.TrimSuffix(c.KeyService, "/mpack")
	}

	if c.VerifyService == "" {
		c.VerifyService = fmt.Sprintf(VERIFY_URL, c.Env)
	}
	return nil
}

// LoadKeys loads the keys map from environment or file
func LoadKeys() (map[string]string, error) {
	var err error
	var keyBytes []byte

	keys := os.Getenv("UBIRCH_KEY_MAP")
	if keys != "" {
		keyBytes = []byte(keys)
	} else {
		keyBytes, err = ioutil.ReadFile(filepath.Join(Path, KeyFile))
		if err != nil {
			return nil, err
		}
	}

	keyMap := make(map[string]string)
	err = json.Unmarshal(keyBytes, &keyMap)
	return keyMap, err
}
