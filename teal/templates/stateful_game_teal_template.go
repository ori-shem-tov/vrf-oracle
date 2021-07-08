package templates

import "text/template"

var StatefulGameTealTemplate *template.Template

var StatefulGameClear = []byte{0x03, 0x20, 0x01, 0x01, 0x22}

func init() {
	var err error
	StatefulGameTealTemplate, err = template.New("TealTemplate").Parse(`#pragma version 3
txn ApplicationID
int 0
==
bnz l14
txn OnCompletion
int DeleteApplication
==
bnz l13
txn OnCompletion
int OptIn
==
bnz l10
txn OnCompletion
int CloseOut
==
bnz l9
txna ApplicationArgs 0
byte "vrf"
==
bnz l6
err
l6:
txna ApplicationArgs 6
sha512_256
byte base64({{.OracleEscrowSuffixHashB64}})
==
txn Sender
byte "Program"
byte base64({{.OracleEscrowPrefixB64}})
concat
byte 0x20
concat
addr {{.OracleOwnerAddress}}
concat
byte 0x08
concat
global CurrentApplicationID
itob
concat
byte 0x03
concat
byte "vrf"
concat
byte 0x08
concat
int 1
byte "block"
app_local_get
concat
byte 0x20
concat
int 1
byte "A"
app_local_get
int 1
byte "B"
app_local_get
concat
int 1
byte "counter"
app_local_get
concat
sha512_256
concat
byte 0x20
concat
txna Accounts 1
concat
byte 0x20
concat
byte base32({{.OracleSigningPKB32}})
concat
txna ApplicationArgs 6
concat
sha512_256
==
&&
!
bz l8
int 0
return
l8:
int 1
byte "vrf"
txna ApplicationArgs 4
app_local_put
int 1
return
l9:
int 0
byte "vrf"
app_local_get
int 63
int 64
substring3
btoi
int 2
%
int 0
==
txna ApplicationArgs 0
byte "A"
==
&&
int 0
byte "vrf"
app_local_get
int 63
int 64
substring3
btoi
int 2
%
int 1
==
txna ApplicationArgs 0
byte "B"
==
&&
||
return
l10:
txna ApplicationArgs 5
sha512_256
byte base64({{.GameEscrowSuffixHashB64}})
==
txn Sender
byte "Program"
byte base64({{.GameEscrowPrefixB64}})
concat
byte 0x01
concat
byte "A"
concat
byte 0x20
concat
txna ApplicationArgs 0
concat
byte 0x01
concat
byte "B"
concat
byte 0x20
concat
txna ApplicationArgs 1
concat
byte 0x08
concat
txna ApplicationArgs 2
concat
txna ApplicationArgs 5
concat
sha512_256
==
&&
!
bz l12
int 0
return
l12:
int 0
byte "A"
txna ApplicationArgs 0
app_local_put
int 0
byte "B"
txna ApplicationArgs 1
app_local_put
int 0
byte "counter"
txna ApplicationArgs 2
app_local_put
int 0
byte "block"
txna ApplicationArgs 3
app_local_put
int 0
byte "expiration"
txna ApplicationArgs 4
app_local_put
int 1
return
l13:
int 1
return
l14:
int 1
return
`)
	if err != nil {
		panic(err)
	}
}
