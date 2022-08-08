import json

from pyteal import *


@Subroutine(TealType.uint64)
def ceiling8(num: Expr):
    return (num + Int(7)) / Int(8)


# return the slot number for the given round
@Subroutine(TealType.bytes)
def get_slot_from_round(rnd: Expr):
    return Itob((ceiling8(rnd) % Int(189)) / Int(3))


# return the inner cell for the given round
@Subroutine(TealType.uint64)
def get_seed_cell_from_round(rnd: Expr):
    return (ceiling8(rnd) % Int(189)) % Int(3)


# a seed can be located in one of 189 cells (63 slots with 3 cells each)
# cells are updated in a cyclic manner
# this Subroutine updates the designated cell inside a given slot
@Subroutine(TealType.bytes)
def update_slot_with_new_seed(slot: Expr, seed: Expr, seed_cell_idx: Expr):
    first = Concat(seed, Extract(slot, Int(32), Int(64)))
    second = Concat(Extract(slot, Int(0), Int(32)), seed, Extract(slot, Int(64), Int(32)))
    third = Concat(Extract(slot, Int(0), Int(64)), seed)
    return Cond(
        [seed_cell_idx == Int(0), first],
        [seed_cell_idx == Int(1), second],
        [seed_cell_idx == Int(2), third],
    )


# update the last updated round
@Subroutine(TealType.none)
def update_last_round(rnd_bytes: Expr):
    return App.globalPut(
        Bytes(''),
        Concat(
            rnd_bytes,
            Extract(
                App.globalGet(Bytes('')),
                Int(8),
                Int(32)
            )
        )
    )


# verify the vrf proof and return the vrf output (the seed)
@Subroutine(TealType.bytes)
def verify_vrf(round: Expr, vrf_proof: Expr, vrf_pk: Expr):
    block_seed = Block.seed(round)
    vrf_verify = VrfVerify.algorand(Sha512_256(Concat(Itob(round), block_seed)), vrf_proof, vrf_pk)
    return Seq([
        vrf_verify,
        Assert(vrf_verify.output_slots[1].load() == Int(1)),
        vrf_verify.output_slots[0].load()
    ])


# store the vrf output (the seed) in its designated cell
@Subroutine(TealType.none)
def store_vrf(rnd: Expr, vrf_output: Expr):
    slot = ScratchVar(TealType.bytes)
    return Seq([
        slot.store(get_slot_from_round(rnd)),
        App.globalPut(
            slot.load(),
            update_slot_with_new_seed(
                App.globalGet(slot.load()),
                Sha512_256(vrf_output),
                get_seed_cell_from_round(rnd)
            )
        )
    ])


# init global state with a constant value
@Subroutine(TealType.none)
def init_global_state(start: Expr, length: Expr, value: Expr):
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


def vrf_beacon_abi():
    router = Router(
        name='Randomness beacon',
        bare_calls=BareCallActions(
            # Blocked opt_in and close_out for now as we don't use any local state (default is CallConfig.NEVER)
            # opt_in=OnCompleteAction(action=Approve(), call_config=CallConfig.CALL),
            # close_out=OnCompleteAction(action=Approve(), call_config=CallConfig.CALL),
            clear_state=OnCompleteAction(action=Approve(), call_config=CallConfig.CALL),
            # Only allow the app creator to delete and update
            delete_application=OnCompleteAction(action=Return(Txn.sender() == Global.creator_address()), call_config=CallConfig.CALL),
            update_application=OnCompleteAction(action=Return(Txn.sender() == Global.creator_address()), call_config=CallConfig.CALL),
        )
    )

    @router.method(no_op=CallConfig.CREATE)
    def create_app(round: abi.Uint64, vrf_proof: abi.String, vrf_pk: abi.Address):
        return Seq([
            # Assert(Len(round.get()) == Int(8)),  # TODO: see if necessary
            Assert(round.get() % Int(8) == Int(0)),
            # Assert(Len(vrf_pk.get()) == Int(32)),  # TODO: see if necessary
            #  init global state to be bytes
            init_global_state(Int(0), Int(63), Bytes(120*'a')),
            # verify the vrf proof and store its output in the correct slot
            store_vrf(
                round.get(),
                verify_vrf(
                    round.get(),
                    vrf_proof.get(),
                    vrf_pk.get()
                )
            ),
            # store the initial round and the VRF public key in their own slot (metadata slot)
            App.globalPut(Bytes(''), Concat(Itob(round.get()), vrf_pk.get()))
        ])

    @router.method(no_op=CallConfig.CALL)
    def submit(round: abi.Uint64, vrf_proof: abi.String):
        return Seq([
            Assert(
                Or(
                    # Submitting proofs is allowed only for subsequent rounds or in case the smart contract is stalled
                    ExtractUint64(App.globalGet(Bytes('')), Int(0)) + Int(8) == round.get(),
                    round.get() - ExtractUint64(App.globalGet(Bytes('')), Int(0)) > Int(1000)
                )
            ),
            # verify the vrf proof and store its output in the correct slot
            store_vrf(
                round.get(),
                verify_vrf(
                    round.get(),
                    vrf_proof.get(),
                    Extract(App.globalGet(Bytes('')), Int(8), Int(32))
                )
            ),
            # update the last submitted round
            update_last_round(Itob(round.get())),
        ])

    @router.method(no_op=CallConfig.CALL)
    def get(round: abi.Uint64, user_data: abi.String, *, output: abi.String):
        # TODO should we enforce output to be of certain minimum length?
        return If(
                    Or(
                        # we check if the requested round is not in the valid window
                        ExtractUint64(App.globalGet(Bytes('')), Int(0)) < round.get(),
                        round.get() + Int(189) * Int(8) <= ExtractUint64(App.globalGet(Bytes('')), Int(0))
                    )
                ).Then(
                    # according to arc-0021, if the requested value can't be found 'get' returns an empty string
                    output.set(
                        Bytes('')
                    )
                ).Else(
                    # if the requested round is in the valid window we return the hash of the concatenation of
                    # the vrf output of the requested round with the user seed
                    output.set(
                        Sha512_256(
                            Concat(
                                Extract(
                                    App.globalGet(get_slot_from_round(round.get())),
                                    Int(32) * get_seed_cell_from_round(round.get()),
                                    Int(32)
                                ),
                                user_data.get()
                            )
                        )
                    )
                )

    @router.method(no_op=CallConfig.CALL)
    def mustGet(round: abi.Uint64, user_data: abi.String, *, output: abi.String):
        # TODO should we enforce output to be of certain minimum length?
        return Seq([
            # according to arc-0021, if the requested value can't be found 'mustGet' panics
            Assert(ExtractUint64(App.globalGet(Bytes('')), Int(0)) >= round.get()),
            Assert(round.get() + Int(189) * Int(8) > ExtractUint64(App.globalGet(Bytes('')), Int(0))),
            # if the requested round is in the valid window we return the hash of the concatenation of
            # the vrf output of the requested round with the user seed
            output.set(
                Sha512_256(
                    Concat(
                        Extract(
                            App.globalGet(get_slot_from_round(round.get())),
                            Int(32) * get_seed_cell_from_round(round.get()),
                            Int(32)
                        ),
                        user_data.get()
                    )
                )
            )
        ])

    return router


if __name__ == '__main__':
    compiled, clear, contract = vrf_beacon_abi().compile_program(version=7)
    filename = 'vrf_beacon_abi_approval.teal'
    with open(filename, 'w') as f:
        f.write(compiled)
        print(f'compiled {filename}')
    filename = 'vrf_beacon_abi_clear.teal'
    with open(filename, 'w') as f:
        f.write(clear)
        print(f'compiled {filename}')
    filename = 'contract.json'
    with open(filename, 'w') as f:
        print(json.dumps(contract.dictify(), indent=4), file=f)
        print(f'compiled {filename}')
