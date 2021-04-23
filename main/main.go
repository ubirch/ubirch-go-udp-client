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
	"github.com/ubirch/ubirch-client-go/main/config"
	"github.com/ubirch/ubirch-client-go/main/handlers"
	"github.com/ubirch/ubirch-client-go/main/uc"
	"os"
	"os/signal"
	"syscall"

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

const configFile = "./config/config.json"

func main() {
	var configDir string
	if len(os.Args) > 1 {
		configDir = os.Args[1]
	}

	log.SetFormatter(&log.JSONFormatter{})
	log.Printf("UBIRCH client (%s, build=%s)", config.Version, config.Build)

	// read configuration
	conf := config.Config{}
	err := conf.Load(configDir, configFile)
	if err != nil {
		log.Fatalf("ERROR: unable to load configuration: %s", err)
	}

	ctxManager, err := handlers.GetCtxManager(conf)
	if err != nil {
		log.Fatal(err)
	}

	// initialize ubirch protocol
	cryptoCtx := &ubirch.ECDSACryptoContext{}

	protocol, err := handlers.NewExtendedProtocol(cryptoCtx, ctxManager)
	if err != nil {
		log.Fatal(err)
	}

	client := &handlers.Client{
		AuthServiceURL:     conf.Niomon,
		VerifyServiceURL:   conf.VerifyService,
		KeyServiceURL:      conf.KeyService,
		IdentityServiceURL: conf.IdentityService,
	}

	idHandler := &handlers.IdentityHandler{
		Protocol:            protocol,
		Client:              client,
		SubjectCountry:      conf.CSR_Country,
		SubjectOrganization: conf.CSR_Organization,
	}

	// generate and register keys for known devices
	if _, ok := ctxManager.(*handlers.FileManager); ok {
		log.Panic("needs to be implemented")
		//err = idHandler.InitIdentities(conf.Devices)
		//if err != nil {
		//	log.Fatal(err)
		//}
	}
	signer := handlers.Signer{
		Protocol: protocol,
		Client:   client,
	}

	verifier := handlers.Verifier{
		Protocol:                      protocol,
		Client:                        client,
		VerifyFromKnownIdentitiesOnly: false, // TODO: make configurable
	}

	httpServer := handlers.HTTPServer{
		Router:   handlers.NewRouter(),
		Addr:     conf.TCP_addr,
		TLS:      conf.TLS,
		CertFile: conf.TLS_CertFile,
		KeyFile:  conf.TLS_KeyFile,
	}
	if conf.CORS && config.IsDevelopment { // never enable CORS on production stage
		httpServer.SetUpCORS(conf.CORS_Origins, conf.Debug)
	}

	globals := handlers.Globals{
		Version: config.Version,
	}


	// create a waitgroup that contains all asynchronous operations
	// a cancellable context is used to stop the operations gracefully
	ctx, cancel := context.WithCancel(context.Background())
	g, ctx := errgroup.WithContext(ctx)

	// set up graceful shutdown handling
	go shutdown(cancel)

	if _, ok := ctxManager.(*handlers.DatabaseManager); ok {
		identity := createIdentityUseCases(globals, ctxManager, idHandler)
		httpServer.Router.Put("/register", identity.handler.Put(identity.storeIdentity, identity.fetchIdentity))
	}

	// set up endpoint for chaining
	httpServer.AddServiceEndpoint(handlers.ServerEndpoint{
		Path: fmt.Sprintf("/{%s}", handlers.UUIDKey),
		Service: &handlers.ChainingService{
			Signer: &signer,
		},
	})

	// set up endpoint for signing
	httpServer.AddServiceEndpoint(handlers.ServerEndpoint{
		Path: fmt.Sprintf("/{%s}/{%s}", handlers.UUIDKey, handlers.OperationKey),
		Service: &handlers.SigningService{

			Signer: &signer,
		},
	})

	// set up endpoint for verification
	httpServer.AddServiceEndpoint(handlers.ServerEndpoint{
		Path: fmt.Sprintf("/%s", handlers.VerifyPath),
		Service: &handlers.VerificationService{
			Verifier: &verifier,
		},
	})

	// start HTTP server
	g.Go(func() error {
		return httpServer.Serve(ctx)
	})

	// wait for all go routines of the waitgroup to return
	if err = g.Wait(); err != nil {
		log.Error(err)
	}

	// wrap up
	if err = protocol.Close(); err != nil {
		log.Error(err)
	}

	log.Info("shut down client")
}

type identities struct {
	handler       handlers.Identity
	storeIdentity handlers.StoreIdentity
	fetchIdentity handlers.FetchIdentity
}

func createIdentityUseCases(globals handlers.Globals, mng handlers.ContextManager, handler *handlers.IdentityHandler) identities {
	return identities{
		handler:       handlers.NewIdentity(globals),
		storeIdentity: uc.NewIdentityStorer(mng, handler),
		fetchIdentity: uc.NewIdentityFetcher(mng),
	}
}
