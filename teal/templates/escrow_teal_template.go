package templates

import "text/template"

var EscrowTealTemplate *template.Template

func init() {
	var err error
	EscrowTealTemplate, err = template.New("TealTemplate").Parse(`#pragma version 3
arg 0
byte "query"
==
bnz l11
arg 0
byte "settlement"
==
bnz l3
err
l3:
global GroupSize
int 2
!=
bnz l9
txn GroupIndex
int 0
==
bnz l8
txn GroupIndex
int 1
==
bnz l7
err
l7:
txn TypeEnum
int pay
==
txn Amount
int 0
==
&&
gtxn 0 TypeEnum
int appl
==
&&
gtxn 0 OnCompletion
int CloseOut
==
&&
gtxna 0 ApplicationArgs 0
byte "A"
==
txn CloseRemainderTo
addr {{.AddressA}}
==
&&
gtxna 0 ApplicationArgs 0
byte "B"
==
txn CloseRemainderTo
addr {{.AddressB}}
==
&&
||
&&
return
l8:
txn TypeEnum
int appl
==
txn OnCompletion
int CloseOut
==
&&
return
l9:
int 0
return
b l12
l11:
byte {{.CounterHex}}
byte {{.CounterHex}}
==
txn RekeyTo
global ZeroAddress
==
&&
global GroupSize
int 4
==
&&
gtxn 0 TypeEnum
int pay
==
gtxn 0 Sender
addr {{.AddressA}}
==
&&
gtxn 0 Receiver
txn Sender
==
&&
&&
gtxn 1 TypeEnum
int pay
==
gtxn 1 Sender
addr {{.AddressB}}
==
&&
gtxn 1 Receiver
txn Sender
==
&&
&&
txn GroupIndex
int 2
==
txn TypeEnum
int appl
==
&&
txn OnCompletion
int OptIn
==
&&
txn GroupIndex
int 3
==
txn TypeEnum
int pay
==
&&
txn CloseRemainderTo
global ZeroAddress
==
&&
||
&&
return
l12:
`)
	if err != nil {
		panic(err)
	}
}
