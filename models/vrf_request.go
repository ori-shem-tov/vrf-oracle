package models

import (
	"github.com/algorand/go-algorand-sdk/types"
)

type VrfRequest struct {
	//OraclePublicKey  ed25519.PublicKey
	//OwnerAddress     types.Address
	Sender           types.Address
	BlockNumber      uint64
	BlockNumberBytes []byte
	UserSeed         []byte
	//AppID            uint64
	//AppIDBytes       [8]byte
	//Arg0             string
}
