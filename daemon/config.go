package daemon

import (
	"strings"

	"github.com/algorand/go-algorand-sdk/crypto"
	"github.com/algorand/go-algorand-sdk/mnemonic"
)

type Config struct {
	AlgodHost  string `json:"algod-host"`
	AlgodPort  int    `json:"algod-port"`
	AlgodToken string `json:"algod-token"`

	DummyAppID int    `json:"dummy-app-id"`
	AppID      int    `json:"app-id"`
	AppHash    string `json:"app-hash"`

	ApprovalSource string `json:"approval"`
	ClearSource    string `json:"clear"`

	WriteInterval int `json:"interval"`
	Start         int `json:"start"`

	Signer  string `json:"signer"`
	VRF     string `json:"vrf"`
	Creator string `json:"creator"`
	Service string `json:"service"`
}

func AccountFromString(secret string) (acct crypto.Account, err error) {
	if !strings.Contains(secret, " ") {
		//TODO: Its a b64 encoded one, decode it and create the acct
		return
	}

	pk, err := mnemonic.ToPrivateKey(secret)
	if err != nil {
		return acct, err
	}

	addr, err := crypto.GenerateAddressFromSK(pk)
	if err != nil {
		return acct, err
	}

	acct = crypto.Account{PrivateKey: pk, Address: addr}

	return
}
