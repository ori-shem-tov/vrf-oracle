import os

from Cryptodome.Hash import SHA512
from pyteal import *
from algosdk import encoding
from algosdk.v2client import algod
from base64 import b32encode, b64encode, b64decode


def vrf_oracle_clear():
    return Seq([
        If(App.localGet(Txn.sender(), Bytes('request_round')) != Int(0)).Then(
            App.globalPut(Bytes('lost_funds'), App.globalGet(Bytes('lost_funds')) + App.globalGet(Bytes('service_fee')))
        ),
        Approve()
    ])


def vrf_oracle_approval():
    on_creation = Seq([
        # 'owner' is the account receiving payments for the service
        App.globalPut(Bytes('owner'), Txn.application_args[0]),
        # 'vrf_service' is the account used by the external service to respond to requests
        App.globalPut(Bytes('vrf_service'), Txn.application_args[1]),
        #  'signing_pk' is the public key used to verify the Ed25519 signature of the responses
        App.globalPut(Bytes('signing_pk'), Txn.application_args[2]),
        #  'service_fee' is the fee payed for the service
        App.globalPut(Bytes('service_fee'), Btoi(Txn.application_args[3])),
        #  'lost_funds' lost funds are fee payed for the service by accounts that cleared/closed-out without cancelling
        App.globalPut(Bytes('lost_funds'), Int(0)),
        #  TODO add the VRF public key when VRFVerify is added to TEAL
        Approve()
    ])

    #  the fee payment transactions is always 1 transaction before the application call
    payment_txn = Gtxn[Txn.group_index() - Int(1)]

    request = Seq([
        #  expected group of at least 2 transactions: fee payment & application call
        Assert(Global.group_size() >= Int(2)),
        #  this application serves as the escrow for the fee
        Assert(payment_txn.receiver() == Global.current_application_address()),
        Assert(payment_txn.type_enum() == TxnType.Payment),
        Assert(payment_txn.amount() == App.globalGet(Bytes('service_fee'))),
        #  make sure the request round is in the future (+ some buffer).
        Assert(Global.round() + Int(10) < Btoi(Txn.application_args[1])),
        #  make sure there is no overlap with a previous request
        Assert(App.localGet(Txn.sender(), Bytes('request_round')) == Int(0)),
        #  'request_round' is the block number from which we take the seed for the vrf computation
        App.localPut(Txn.sender(), Bytes('request_round'), Btoi(Txn.application_args[1])),
        #  'user_seed' is the user seed used in the vrf computation
        App.localPut(Txn.sender(), Bytes('user_seed'), Txn.application_args[2]),
        Int(1)
    ])

    respond = Seq([
        #  responses are only accepted from the 'vrf_service' account
        Assert(Txn.sender() == App.globalGet(Bytes('vrf_service'))),
        #  making sure the external service is responding on the correct request
        Assert(App.localGet(Txn.accounts[1], Bytes('request_round')) == Btoi(Txn.application_args[1])),
        #  verifying response's signature
        Assert(Ed25519Verify(
            Concat(
                Txn.application_args[1],  # round
                Txn.application_args[2],  # block seed
                App.localGet(Txn.accounts[1], Bytes('user_seed')),
                Txn.application_args[3],  # vrf output
            ),
            Txn.application_args[4],
            App.globalGet(Bytes('signing_pk'))
        )),
        #  resetting 'request_round' to allow more requests in the future
        App.localPut(Txn.accounts[1], Bytes('request_round'), Int(0)),
        #  storing the vrf output in local storage
        App.localPut(Txn.accounts[1], Bytes('response'), Txn.application_args[3]),
        #  transfer the service fee to the owner address.
        InnerTxnBuilder.Begin(),
        InnerTxnBuilder.SetFields(
            {
                TxnField.type_enum: TxnType.Payment,
                TxnField.receiver: App.globalGet(Bytes('owner')),
                TxnField.amount: App.globalGet(Bytes('service_fee')),
                TxnField.fee: Int(0),
            }
        ),
        InnerTxnBuilder.Submit(),
        Int(1)
    ])

    cancel = Seq([
        Assert(
            Or(
                #  make sure the request round is in the future (+ some buffer).
                Global.round() + Int(5) < App.localGet(Txn.sender(), Bytes('request_round')),
                #  or response takes too long
                And(
                    App.localGet(Txn.sender(), Bytes('request_round')) != Int(0),
                    Global.round() > App.localGet(Txn.sender(), Bytes('request_round')) + Int(100)
                )
            )
        ),
        #  resetting 'request_round' to allow more requests in the future
        App.localPut(Txn.sender(), Bytes('request_round'), Int(0)),
        #  transfer the service fee to the requester address.
        InnerTxnBuilder.Begin(),
        InnerTxnBuilder.SetFields(
            {
                TxnField.type_enum: TxnType.Payment,
                TxnField.receiver: Txn.sender(),
                TxnField.amount: App.globalGet(Bytes('service_fee')),
                TxnField.fee: Int(0),
            }
        ),
        InnerTxnBuilder.Submit(),
        Int(1)
    ])

    withdraw_lost_funds = Seq([
        Assert(Txn.sender() == App.globalGet(Bytes('owner'))),
        InnerTxnBuilder.Begin(),
        InnerTxnBuilder.SetFields(
            {
                TxnField.type_enum: TxnType.Payment,
                TxnField.receiver: Txn.sender(),
                TxnField.amount: App.globalGet(Bytes('lost_funds')),
                TxnField.fee: Int(0),
            }
        ),
        InnerTxnBuilder.Submit(),
        App.globalPut(Bytes('lost_funds'), Int(0)),
        Int(1)
    ])

    program = Cond(
        #  handle app creation
        [Txn.application_id() == Int(0), on_creation],
        #  allow all to opt-in and close-out
        [Txn.on_completion() == OnComplete.OptIn, Approve()],
        [Txn.on_completion() == OnComplete.CloseOut, vrf_oracle_clear()],
        #  allow creator to update and delete app
        [Txn.on_completion() == OnComplete.DeleteApplication, Return(Txn.sender() == Global.creator_address())],
        [Txn.on_completion() == OnComplete.UpdateApplication, Return(Txn.sender() == Global.creator_address())],
        [
            Txn.on_completion() == OnComplete.NoOp,
            Cond(
                [Txn.application_args[0] == Bytes('request'),
                 Return(request)],
                [Txn.application_args[0] == Bytes('respond'),
                 Return(respond)],
                [Txn.application_args[0] == Bytes('cancel'),
                 Return(cancel)],
                [Txn.application_args[0] == Bytes('withdraw_lost_funds'),
                 Return(withdraw_lost_funds)]
            )
        ]
    )

    return program


if __name__ == '__main__':
    filename = 'vrf_oracle_approval.teal'
    with open(filename, 'w') as f:
        compiled = compileTeal(
            vrf_oracle_approval(),
            Mode.Application, version=5
        )
        f.write(compiled)
        print(f'compiled {filename}')

    filename = 'vrf_oracle_clear.teal'
    with open(filename, 'w') as f:
        compiled = compileTeal(vrf_oracle_clear(), Mode.Application, version=5)
        f.write(compiled)
        print(f'compiled {filename}')

