package main

import (
	"time"

	log "github.com/sirupsen/logrus"
)

const (
	clientBaseURL1         = "http://localhost:8080"
	clientBaseURL2         = "http://localhost:8080"
	clientBaseURL3         = "http://localhost:8080"
	clientBaseURL4         = "http://localhost:8080"
	configFile             = "config.json"
	numberOfTestIDs        = 10
	numberOfRequestsPerID  = 1000
	requestsPerSecondPerID = 4
)

func main() {
	testCtx := NewTestCtx()
	sender := NewSender(testCtx)

	//for id, auth := range testCtx.identities {
	//	err := sender.register(id, auth, testCtx.registerAuth)
	//	if err != nil {
	//		log.Fatal(err)
	//	}
	//}

	log.Infof("%d identities, %d requests each => sending [ %d ] requests", len(testCtx.identities), numberOfRequestsPerID, len(testCtx.identities)*numberOfRequestsPerID)
	log.Infof("%3d requests per second per identity", requestsPerSecondPerID)
	log.Infof("%3d requests per second overall", len(testCtx.identities)*requestsPerSecondPerID)

	start := time.Now()

	for uid, auth := range testCtx.identities {
		testCtx.wg.Add(1)
		go sender.sendRequests(uid, auth)
	}

	testCtx.wg.Wait()
	log.Infof(" = = = => requests done after [ %7.3f ] seconds <= = = = ", time.Since(start).Seconds())
	testCtx.finish()
}
