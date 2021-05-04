package main

import (
	"encoding/base32"
	"fmt"
	"github.com/algorand/go-algorand-sdk/client/v2/algod"
	"github.com/algorand/go-algorand-sdk/types"
	"strconv"
	"strings"
)

var allowedArg0 = map[string]bool{"vrf": true}

type OracleTealParams struct {
	AppIDHex string
	Arg0 string
	Block string
	Xb32 string
	Sender types.Address
	SigningPKb32 string
	OwnerAddr types.Address
}

func checkBase32Str(base32Str string) error {
	decoded, err := base32.StdEncoding.DecodeString(base32Str)
	if err != nil || len(decoded) != 32 {
		return fmt.Errorf("should be a 32 byte slice encoded in base32")
	}
	return nil
}

func (oracleTealParams *OracleTealParams) Validate() error {
	var errors []string
	_, err := strconv.ParseUint(oracleTealParams.AppIDHex, 0, 64)
	if err != nil || len(oracleTealParams.AppIDHex) != 18 || oracleTealParams.AppIDHex[:2] != "0x" {
		errors = append(errors, "AppIDHex should be a string of 8 byte hex number")
	}
	if _, ok := allowedArg0[oracleTealParams.Arg0]; !ok {
		errors = append(errors, fmt.Sprintf("invalid Arg0: got %s, allowed %v", oracleTealParams.Arg0, allowedArg0))
	}
	_, err = strconv.ParseUint(oracleTealParams.Block, 10, 64)
	if err != nil || len(oracleTealParams.Block) != 8 {
		errors = append(errors, "Block should be an 8 byte string of an integer")
	}
	err = checkBase32Str(oracleTealParams.Xb32)
	if err != nil {
		errors = append(errors, fmt.Sprintf("Xb32 %v", err))
	}
	err = checkBase32Str(oracleTealParams.SigningPKb32)
	if err != nil {
		errors = append(errors, fmt.Sprintf("SigningPKb32 %v", err))
	}
	if len(errors) != 0 {
		return fmt.Errorf(strings.Join(errors, ", "))
	}
	return nil
}

// CompileOracle compiles ths oracle teal program
func CompileOracle(oracleTealParams OracleTealParams, algodClient *algod.Client) ([]byte, error) {
	return CompileTeal(&oracleTealParams, OracleTealTemplate, algodClient)
}
