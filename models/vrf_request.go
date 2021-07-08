package models

import (
	"crypto/ed25519"
	"encoding/base32"
	"fmt"
	"github.com/algorand/go-algorand-sdk/types"
	"github.com/ori-shem-tov/vrf-oracle/teal/compile"
)

type VrfRequest struct {
	OraclePublicKey  ed25519.PublicKey
	OwnerAddress     types.Address
	Sender           types.Address
	BlockNumber      uint64
	BlockNumberBytes [8]byte
	X                [32]byte
	AppID            uint64
	AppIDBytes       [8]byte
	Arg0             string
}

func (r *VrfRequest) OracleTealParams() (compile.OracleTealParams, error) {
	var result compile.OracleTealParams

	result.Arg0 = r.Arg0
	result.AppIDHex = fmt.Sprintf("0x%016x", r.AppID)
	result.Block = fmt.Sprintf("%08d", r.BlockNumber)
	result.Sender = r.Sender
	result.OwnerAddr = r.OwnerAddress
	result.SigningPKb32 = base32.StdEncoding.EncodeToString(r.OraclePublicKey)
	result.Xb32 = base32.StdEncoding.EncodeToString(r.X[:])

	return result, result.Validate()
}
