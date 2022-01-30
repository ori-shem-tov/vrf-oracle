import os

from pyteal import *


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


@Subroutine(TealType.uint64)
def ceiling8(num: TealType.uint64) -> TealType.uint64:
    return (num + Int(7)) / Int(8)


@Subroutine(TealType.bytes)
def get_slot_from_round(rnd: TealType.uint64) -> TealType.bytes:
    return Itob((ceiling8(rnd) % Int(189)) / Int(3))


@Subroutine(TealType.uint64)
def get_seed_index_from_round(rnd: TealType.uint64) -> TealType.uint64:
    return (ceiling8(rnd) % Int(189)) % Int(3)


@Subroutine(TealType.bytes)
def generate_slot_with_new_seed(slot: TealType.bytes, seed: TealType.bytes, seed_idx: TealType.uint64) -> TealType.bytes:
    first = Concat(seed, Extract(slot, Int(32), Int(64)))
    second = Concat(Extract(slot, Int(0), Int(32)), seed, Extract(slot, Int(64), Int(32)))
    third = Concat(Extract(slot, Int(0), Int(64)), seed)
    return Cond(
        [seed_idx == Int(0), first],
        [seed_idx == Int(1), second],
        [seed_idx == Int(2), third],
    )


@Subroutine(TealType.none)
def update_last_round(rnd_bytes: TealType.bytes):
    return App.globalPut(
        Bytes(''),
        Concat(
            rnd_bytes,
            Extract(
                App.globalGet(Bytes('')),
                Int(8),
                Int(64)
            )
        )
    )


@Subroutine(TealType.none)
def validate_vrf(round_bytes: TealType.bytes, block_seed: TealType.bytes,
                 vrf_output: TealType.bytes, sig: TealType.bytes, signing_pk: TealType.bytes):
    return Assert(Ed25519Verify(
            Concat(
                round_bytes,
                block_seed,
                vrf_output,  # TODO once we have VRFVerify, this should be the vrf proof
            ),
            sig,
            signing_pk
        ))


@Subroutine(TealType.none)
def store_vrf(rnd: TealType.uint64, vrf_output: TealType.bytes):
    slot = ScratchVar(TealType.bytes)
    return Seq([
        slot.store(get_slot_from_round(rnd)),
        App.globalPut(
            slot.load(),
            generate_slot_with_new_seed(
                App.globalGet(slot.load()),
                Sha512_256(vrf_output),
                get_seed_index_from_round(rnd)
            )
        )
    ])


@Subroutine(TealType.none)
def init_global_state(start: TealType.uint64, length: TealType.uint64, value: TealType.bytes):
    i = ScratchVar(TealType.uint64)
    init = i.store(start)
    cond = i.load() < length
    itr = i.store(i.load() + Int(1))
    return For(init, cond, itr).Do(
        App.globalPut(
            Itob(i.load()),
            value
        )
    )


def vrf_beacon_approval():
    on_creation = Seq([
        Assert(Len(Txn.application_args[0]) == Int(8)),   # round is uint64
        Assert(Len(Txn.application_args[1]) == Int(32)),  # signingPK
        Assert(Len(Txn.application_args[2]) == Int(32)),  # vrfPK
        validate_vrf(
            Txn.application_args[0],  # round
            Txn.application_args[3],  # block seed
            Txn.application_args[4],  # vrf output TODO once we have VRFVerify, this should be the vrf proof
            Txn.application_args[5],  # signature
            Txn.application_args[1],  # signingPK
        ),
        #  init global state to be bytes
        init_global_state(Int(0), Int(63), Bytes('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa')),
        store_vrf(Btoi(Txn.application_args[0]), Txn.application_args[4]),
        #  storing metadata round|signingPK|vrfPK
        App.globalPut(Bytes(''), Concat(Txn.application_args[0], Txn.application_args[1], Txn.application_args[2])),
        #  TODO consider what to do when service is down for more than 1000 rounds
        Approve()
    ])

    rnd = ScratchVar(TealType.uint64)

    respond = Seq([
        rnd.store(Btoi(Txn.application_args[1])),
        #  making sure the external service is responding on the correct request which last_round_stored + 8
        #  we update randomness every 8 rounds
        #  last_round_stored is stored as the first 8 bytes in metadata
        Assert(ExtractUint64(App.globalGet(Bytes('')), Int(0)) + Int(8) == rnd.load()),
        #  verifying response's signature
        validate_vrf(
            Txn.application_args[1],  # round
            Txn.application_args[2],  # block seed
            Txn.application_args[3],  # vrf output TODO once we have VRFVerify, this should be the vrf proof
            Txn.application_args[4],  # signature
            #  signingPK is stored as the 32 bytes after last_round_stored in metadata
            Extract(App.globalGet(Bytes('')), Int(8), Int(32))
        ),
        #  update slot with new vrf
        store_vrf(rnd.load(), Txn.application_args[3]),
        update_last_round(Txn.application_args[1]),
        Int(1)
    ])

    request = Seq([
        rnd.store(Btoi(Txn.application_args[1])),
        Assert(ExtractUint64(App.globalGet(Bytes('')), Int(0)) >= rnd.load()),
        Assert(rnd.load() + Int(189) * Int(8) > ExtractUint64(App.globalGet(Bytes('')), Int(0))),
        Log(
            Extract( #  TODO return the hash of this value concat with the current round and a user seed
                App.globalGet(get_slot_from_round(rnd.load())),
                Int(32) * get_seed_index_from_round(rnd.load()),
                Int(32)
            )
        ),
        Int(1)
    ])

    program = Cond(
        #  handle app creation
        [Txn.application_id() == Int(0), on_creation],
        #  allow all to opt-in and close-out
        [Txn.on_completion() == OnComplete.OptIn, Approve()],
        [Txn.on_completion() == OnComplete.CloseOut, Approve()],
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

    filename = 'vrf_beacon_approval.teal'
    with open(filename, 'w') as f:
        compiled = compileTeal(
            vrf_beacon_approval(),
            Mode.Application, version=5)
        f.write(compiled)
        print(f'compiled {filename}')
    filename = 'vrf_beacon_clear.teal'
    with open(filename, 'w') as f:
        compiled = compileTeal(
            Approve(),
            Mode.Application, version=5)
        f.write(compiled)
        print(f'compiled {filename}')

