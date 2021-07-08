package templates

import "text/template"

var OracleTealTemplate *template.Template

func init() {
	var err error
	OracleTealTemplate, err = template.New("TealTemplate").Parse(`#pragma version 3
global GroupSize
int 2
!=
bnz l6
txn GroupIndex
int 0
==
bnz l5
txn GroupIndex
int 1
==
bnz l4
err
l4:
txn TypeEnum
int pay
==
txn Amount
int 0
==
&&
txn CloseRemainderTo
addr {{.OwnerAddr}}
==
&&
return
l5:
txn TypeEnum
int appl
==
txn ApplicationID
byte {{.AppIDHex}}
btoi
==
&&
txna ApplicationArgs 0
byte "{{.Arg0}}"
==
&&
txna ApplicationArgs 1
byte "{{.Block}}"
==
&&
txna ApplicationArgs 3
byte base32({{.Xb32}})
==
&&
txna Accounts 1
addr {{.Sender}}
==
&&
txn Sender
byte "{{.Block}}"
concat
txna ApplicationArgs 2
concat
byte base32({{.Xb32}})
concat
txna ApplicationArgs 4
concat
arg 0
byte base32({{.SigningPKb32}})
ed25519verify
&&
return
l6:
int 0
return
`)
	if err != nil {
		panic(err)
	}
}
