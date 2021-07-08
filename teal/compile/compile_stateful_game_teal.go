package compile

import (
	"encoding/base32"
	"encoding/base64"
	"fmt"
	"github.com/algorand/go-algorand-sdk/client/v2/algod"
	"github.com/algorand/go-algorand-sdk/types"
	"github.com/ori-shem-tov/vrf-oracle/teal/templates"
	"strings"
)

type StatefulGameTealParams struct {
	GameEscrowPrefixB64 string
	GameEscrowSuffixHashB64 string
	OracleSigningPKB32 string
	OracleOwnerAddress types.Address
	OracleEscrowPrefixB64 string
	OracleEscrowSuffixHashB64 string
}

func (statefulGameTealParams *StatefulGameTealParams) Validate() error {
	var errors []string
	_, err := base64.StdEncoding.DecodeString(statefulGameTealParams.GameEscrowPrefixB64)
	if err != nil {
		errors = append(errors, "invalid GameEscrowPrefixB64")
	}
	_, err = base64.StdEncoding.DecodeString(statefulGameTealParams.GameEscrowSuffixHashB64)
	if err != nil {
		errors = append(errors, "invalid GameEscrowSuffixHashB64")
	}
	_, err = base64.StdEncoding.DecodeString(statefulGameTealParams.OracleEscrowPrefixB64)
	if err != nil {
		errors = append(errors, "invalid OracleEscrowPrefixB64")
	}
	_, err = base64.StdEncoding.DecodeString(statefulGameTealParams.OracleEscrowSuffixHashB64)
	if err != nil {
		errors = append(errors, "invalid OracleEscrowSuffixHashB64")
	}
	_, err = base32.StdEncoding.DecodeString(statefulGameTealParams.OracleSigningPKB32)
	if err != nil {
		errors = append(errors, "invalid OracleSigningPKB32")
	}
	if len(errors) != 0 {
		return fmt.Errorf(strings.Join(errors, ", "))
	}
	return nil
}

func CompileStatefulGame(params StatefulGameTealParams, algodClient *algod.Client) ([]byte, error) {
	return CompileTeal(&params, templates.StatefulGameTealTemplate, algodClient)
}