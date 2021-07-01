package ent

import "github.com/google/uuid"

type Identity struct {
	Uid        uuid.UUID
	PrivateKey []byte
	PublicKey  []byte
	Signature  []byte
	AuthToken  string
}
