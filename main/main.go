/*
 * Copyright (c) 2019 ubirch GmbH
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/google/uuid"
	"github.com/ubirch/ubirch-go-http-server/api"
	"github.com/ubirch/ubirch-protocol-go/ubirch/v2"
)

const (
	ConfigFile  = "config.json"
	ContextFile = "protocol.json"
)

var (
	Version = "v1.0.0"
	Build   = "local"
)

// handle graceful shutdown
func shutdown(signals chan os.Signal, p *ExtendedProtocol, wg *sync.WaitGroup, cancel context.CancelFunc) {
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)

	// block until we receive a SIGINT or SIGTERM
	sig := <-signals
	log.Printf("shutting down after receiving: %v", sig)

	// wait for all go routines to end, cancels the go routines contexts
	// and waits for the wait group
	cancel()
	wg.Wait()

	err := p.SaveContext()
	if err != nil {
		log.Printf("unable to save protocol context: %v", err)
		os.Exit(1)
	}

	os.Exit(0)
}

func main() {
	pathToConfig := ""
	if len(os.Args) > 1 {
		pathToConfig = os.Args[1]
	}

	log.Printf("ubirch Golang client (%s, build=%s)", Version, Build)

	// read configuration
	conf := Config{}
	err := conf.Load(pathToConfig + ConfigFile)
	if err != nil {
		log.Fatalf("Error loading config: %s", err)
	}

	// create an ubirch protocol instance
	p := ExtendedProtocol{}
	p.Crypto = &ubirch.CryptoContext{
		Keystore: ubirch.NewEncryptedKeystore(conf.Secret),
		Names:    map[string]uuid.UUID{},
	}
	p.Signatures = map[uuid.UUID][]byte{}
	p.Certificates = map[uuid.UUID]SignedKeyRegistration{}
	p.DNS = conf.DSN
	p.ContextFile = pathToConfig + ContextFile

	// try to read an existing protocol context (keystore)
	err = p.LoadContext()
	if err != nil {
		log.Printf("empty keystore: %v", err) // fixme
	} else {
		log.Printf("loaded protocol context")
		log.Printf("%d certificates, %d signatures\n", len(p.Certificates), len(p.Signatures))
	}

	// todo load keys from key file / env variable into keystore

	//
	//keysMap, err = LoadKeys() // todo pathToConfig + ConfigFile
	//if err != nil {           // todo is this really critical?
	//	log.Fatalf("ERROR: unable to read keys from env: %v", err)
	//}
	//	// set keys
	//if key, exists := keys[name]; exists { // todo feed keys to proto instance at init
	//	keyBytes, err := base64.StdEncoding.DecodeString(key)
	//	if err != nil {
	//		log.Printf("Error decoding private key string for %s: %v, string was: %s", name, err, keyBytes)
	//		continue
	//	}
	//	err = p.Crypto.SetKey(name, uid, keyBytes)
	//	if err != nil {
	//		log.Printf("Error inserting private key: %v,", err)
	//		continue
	//	}
	//

	//if conf.DSN != "" {
	//	// use the database
	//	db, err = NewPostgres(conf.DSN)
	//	if err != nil {
	//		log.Fatalf("Could not connect to database: %s", err)
	//	}
	//
	//	err = db.GetProtocolContext(&p)
	//	if err != nil {
	//		log.Printf("empty keystore: %v", err)
	//	}
	//	p.DB = db
	//
	//} else {
	//	// read configurations from file
	//	// try to read an existing p context (keystore)
	//	err = p.load() // todo there should be one p.load and one p.save
	//	if err != nil {
	//		log.Printf("empty keystore: %v", err)
	//	}
	//}

	// create a waitgroup that contains all asynchronous operations
	// a cancellable context is used to stop the operations gracefully
	wg := sync.WaitGroup{}
	ctx, cancel := context.WithCancel(context.Background())

	// set up graceful shutdown handling
	signals := make(chan os.Signal, 1)
	go shutdown(signals, &p, &wg, cancel)

	// create a messages channel that parses the HTTP message and creates UPPs
	msgsToSign := make(chan api.HTTPMessage, 100)
	go signer(msgsToSign, &p, conf, ctx, &wg)
	wg.Add(1)

	// listen to messages to sign via http
	httpSrvSign := api.HTTPServer{MessageHandler: msgsToSign, Endpoint: "/sign", Auth: conf.Password}
	httpSrvSign.Serve(ctx, &wg)
	wg.Add(1)

	// wait forever, exit is handled via shutdown
	select {}
}
