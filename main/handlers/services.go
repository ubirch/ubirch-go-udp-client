package handlers

import (
	"fmt"
	"github.com/go-chi/chi"
	"github.com/google/uuid"
	h "github.com/ubirch/ubirch-client-go/main/handlers/httphelper"
	"net/http"

	log "github.com/sirupsen/logrus"
)

type Service interface {
	HandleRequest(w http.ResponseWriter, r *http.Request)
}

type ChainingService struct {
	*Signer
}

// Ensure ChainingService implements the Service interface
var _ Service = (*ChainingService)(nil)

func (c *ChainingService) HandleRequest(w http.ResponseWriter, r *http.Request) {
	var msg h.HTTPRequest
	var err error

	ctx := r.Context()

	msg.ID, err = h.GetUUID(r)
	if err != nil {
		h.Error(msg.ID, w, err, http.StatusNotFound)
		return
	}

	// todo here we need to check if the UUID is known

	idAuth, err := c.Protocol.GetAuthToken(msg.ID)
	if err != nil {
		h.Error(msg.ID, w, err, http.StatusInternalServerError)
		return
	}

	msg.Auth, err = h.CheckAuth(r, idAuth)
	if err != nil {
		log.Errorf("something went wrong: %v", err)
		h.Error(msg.ID, w, err, http.StatusUnauthorized)
		return
	}

	msg.Hash, err = h.GetHash(r)
	if err != nil {
		log.Errorf("something went wrong get hash: %v", err)
		h.Error(msg.ID, w, err, http.StatusBadRequest)
		return
	}

	// todo here goes the waiting loop
	resp, err := c.Protocol.ContextManager.SendChainedUpp(ctx, msg, c.Signer)
	if err != nil {
		log.Errorf("something went wrong send chain: %v", err)
		h.Error(msg.ID, w, err, http.StatusInternalServerError)
		return
	}

	h.SendResponse(w, *resp)
}

type SigningService struct {
	*Signer
}

var _ Service = (*SigningService)(nil)

func (s *SigningService) HandleRequest(w http.ResponseWriter, r *http.Request) {
	var msg h.HTTPRequest
	var err error

	msg.ID, err = h.GetUUID(r)
	if err != nil {
		h.Error(msg.ID, w, err, http.StatusNotFound)
		return
	}

	// todo here we need to check if the UUID is known

	idAuth, err := s.Protocol.GetAuthToken(msg.ID)
	if err != nil {
		h.Error(msg.ID, w, err, http.StatusInternalServerError)
		return
	}

	msg.Auth, err = h.CheckAuth(r, idAuth)
	if err != nil {
		h.Error(msg.ID, w, err, http.StatusUnauthorized)
		return
	}

	op, err := getOperation(r)
	if err != nil {
		h.Error(msg.ID, w, err, http.StatusNotFound)
		return
	}

	msg.Hash, err = h.GetHash(r)
	if err != nil {
		h.Error(msg.ID, w, err, http.StatusBadRequest)
		return
	}

	resp := s.Sign(msg, op)
	h.SendResponse(w, resp)
}

type VerificationService struct {
	*Verifier
}

var _ Service = (*VerificationService)(nil)

func (v *VerificationService) HandleRequest(w http.ResponseWriter, r *http.Request) {
	hash, err := h.GetHash(r)
	if err != nil {
		h.Error(uuid.Nil, w, err, http.StatusBadRequest)
		return
	}

	resp := v.Verify(hash[:])
	h.SendResponse(w, resp)
}

// getOperation returns the operation parameter from the request URL
func getOperation(r *http.Request) (operation, error) {
	opParam := chi.URLParam(r, h.OperationKey)
	switch operation(opParam) {
	case anchorHash, disableHash, enableHash, deleteHash:
		return operation(opParam), nil
	default:
		return "", fmt.Errorf("invalid operation: "+
			"expected (\"%s\" | \"%s\" | \"%s\" | \"%s\"), got \"%s\"",
			anchorHash, disableHash, enableHash, deleteHash, opParam)
	}
}
