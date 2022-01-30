package compile

import (
	"context"
	"encoding/base64"
	"strings"
	"text/template"

	"github.com/algorand/go-algorand-sdk/client/v2/algod"
	"github.com/algorand/go-algorand-sdk/logic"
)

type TealParams interface {
	Validate() error
}

func CompileTeal(tealParams TealParams, tealTemplate *template.Template, algodClient *algod.Client) ([]byte, error) {
	if err := tealParams.Validate(); err != nil {
		return []byte{}, err
	}

	var sb strings.Builder
	// write the filled template to string builder
	if err := tealTemplate.Execute(&sb, tealParams); err != nil {
		return []byte{}, err
	}

	// compile the logic sig
	response, err := algodClient.TealCompile([]byte(sb.String())).Do(context.Background())
	if err != nil {
		return []byte{}, err
	}
	program, err := base64.StdEncoding.DecodeString(response.Result)
	if err != nil {
		return []byte{}, err
	}
	if err := logic.CheckProgram(program, nil); err != nil {
		return []byte{}, err
	}

	return program, nil
}
