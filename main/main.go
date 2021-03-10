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
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/google/uuid"
	"github.com/ubirch/ubirch-protocol-go/ubirch/v2"
	"golang.org/x/sync/errgroup"

	log "github.com/sirupsen/logrus"
)

// handle graceful shutdown
func shutdown(cancel context.CancelFunc) {
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)

	// block until we receive a SIGINT or SIGTERM
	sig := <-signals
	log.Printf("shutting down after receiving: %v", sig)

	// cancel the go routines contexts
	cancel()
}

func main() {
	const (
		Version     = "v2.0.0"
		Build       = "local"
		configFile  = "config.json"
		contextFile = "protocol.json"
	)

	var configDir string
	if len(os.Args) > 1 {
		configDir = os.Args[1]
	}

	log.SetFormatter(&log.JSONFormatter{})
	log.Printf("UBIRCH client (%s, build=%s)", Version, Build)

	// read configuration
	conf := Config{}
	err := conf.Load(configDir, configFile)
	if err != nil {
		log.Fatalf("ERROR: unable to load configuration: %s", err)
	}

	// create an ubirch protocol instance
	p := ExtendedProtocol{}
	p.Crypto = &ubirch.CryptoContext{
		Keystore: ubirch.NewEncryptedKeystore(conf.SecretBytes),
		Names:    map[string]uuid.UUID{},
	}
	p.Signatures = map[uuid.UUID][]byte{}

	err = p.Init(configDir, contextFile, conf.DSN, conf.Keys)
	if err != nil {
		log.Fatal(err)
	}

	// generate and register keys for known devices
	err = initDeviceKeys(&p, conf)
	if err != nil {
		log.Fatal(err)
	}

	// insert backend public key into keystore for verification of server responses
	err = setPublicKey(&p, conf.Env, conf.ServerIdentity.UUID, conf.ServerIdentity.PubKey.ECDSA)
	if err != nil {
		log.Fatal(err)
	}

	// create a waitgroup that contains all asynchronous operations
	// a cancellable context is used to stop the operations gracefully
	ctx, cancel := context.WithCancel(context.Background())
	g, ctx := errgroup.WithContext(ctx)

	// set up graceful shutdown handling
	go shutdown(cancel)

	// set up HTTP server
	httpServer := HTTPServer{
		router:   NewRouter(),
		addr:     conf.TCP_addr,
		TLS:      conf.TLS,
		certFile: conf.TLS_CertFile,
		keyFile:  conf.TLS_KeyFile,
	}
	if conf.CORS && conf.Env != PROD_STAGE { // never enable CORS on production stage
		httpServer.SetUpCORS(conf.CORS_Origins, conf.Debug)
	}

	// listen to messages to sign via http
	httpSrvSign := ServerEndpoint{
		Path:           fmt.Sprintf("/{%s}", UUIDKey),
		MessageHandler: make(chan HTTPMessage, 100),
		RequiresAuth:   true,
		AuthTokens:     conf.Devices,
	}
	httpServer.AddEndpoint(httpSrvSign)

	// listen to messages to verify via http
	httpSrvVerify := ServerEndpoint{
		Path:           "/verify",
		MessageHandler: make(chan HTTPMessage, 100),
		RequiresAuth:   false,
		AuthTokens:     nil,
	}
	httpServer.AddEndpoint(httpSrvVerify)

	// start signer
	g.Go(func() error {
		return signer(ctx, httpSrvSign.MessageHandler, &p, conf)
	})

	// start verifier
	g.Go(func() error {
		return verifier(ctx, httpSrvVerify.MessageHandler, &p, conf)
	})

	// start HTTP server
	g.Go(func() error {
		return httpServer.Serve(ctx)
	})

	//wait until all function calls from the Go method have returned
	if err = waitUntilDone(g, p); err != nil {
		log.Fatal(err)
	}
}

func waitUntilDone(g *errgroup.Group, p ExtendedProtocol) error {
	groupErr := g.Wait()

	if err := p.Deinit(); err != nil {
		log.Error(err)
	}

	return groupErr
}
