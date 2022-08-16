import json
from typing import Literal

from pyteal import *

NB_OF_SLOTS = 63
NB_OF_CELLS_PER_SLOT = 3
NB_OF_STORED_VRF_OUTPUTS = NB_OF_SLOTS * NB_OF_CELLS_PER_SLOT
SUBMIT_VAL_GAP = 8
NB_RETAINED_BLOCKS = 1000
NB_GRACE_BLOCKS = 2 * SUBMIT_VAL_GAP
HASH_LENGTH = 32


@Subroutine(TealType.uint64)
def ceiling8(num: Expr):
    return ((num + Int(SUBMIT_VAL_GAP - 1)) / Int(SUBMIT_VAL_GAP)) * Int(SUBMIT_VAL_GAP)


# return the slot number for the given round
@Subroutine(TealType.bytes)
def get_slot_from_round(round: Expr):
    return Itob(((ceiling8(round) / Int(SUBMIT_VAL_GAP)) % Int(NB_OF_STORED_VRF_OUTPUTS)) / Int(NB_OF_CELLS_PER_SLOT))


# return the inner cell for the given round
@Subroutine(TealType.uint64)
def get_vrf_output_cell_from_round(round: Expr):
    return ((ceiling8(round) / Int(SUBMIT_VAL_GAP)) % Int(NB_OF_STORED_VRF_OUTPUTS)) % Int(NB_OF_CELLS_PER_SLOT)


# a VRF output can be located in one of 189 cells (63 slots with 3 cells each)
# cells are updated in a cyclic manner
# this Subroutine updates the designated cell inside a given slot
@Subroutine(TealType.bytes)
def update_slot_with_new_vrf_output(slot: Expr, vrf_output: Expr, vrf_output_cell_idx: Expr):
    first = Concat(vrf_output, Extract(slot, Int(HASH_LENGTH), Int(2 * HASH_LENGTH)))
    second = Concat(Extract(slot, Int(0), Int(HASH_LENGTH)), vrf_output,
                    Extract(slot, Int(2 * HASH_LENGTH), Int(HASH_LENGTH)))
    third = Concat(Extract(slot, Int(0), Int(2 * HASH_LENGTH)), vrf_output)
    return Cond(
        [vrf_output_cell_idx == Int(0), first],
        [vrf_output_cell_idx == Int(1), second],
        [vrf_output_cell_idx == Int(2), third],
    )


# update the last updated round
def update_last_round(last_round: Expr):
    return App.globalPut(
        Bytes(''),
        Concat(
            Itob(last_round),
            Itob(get_first_stored_vrf_round()),
            get_vrf_pk()
        )
    )


# update the first updated round
def update_first_round(first_round: Expr):
    return App.globalPut(
        Bytes(''),
        Concat(
            Itob(get_last_stored_vrf_round()),
            Itob(first_round),
            get_vrf_pk()
        )
    )


# verify the VRF proof and return the VRF output
@Subroutine(TealType.bytes)
def verify_vrf(round: Expr, vrf_proof: Expr, vrf_pk: Expr):
    block_seed = Block.seed(round)  # as a security measure, this will fail if seed is unavailable
    vrf_verify = VrfVerify.algorand(Sha512_256(Concat(Itob(round), block_seed)), vrf_proof, vrf_pk)
    return Seq([
        vrf_verify,
        Assert(vrf_verify.output_slots[1].load() == Int(1)),
        vrf_verify.output_slots[0].load()
    ])


# store the VRF output in its designated cell
@Subroutine(TealType.none)
def store_vrf(round: Expr, vrf_output: Expr):
    slot = ScratchVar(TealType.bytes)
    return Seq([
        slot.store(get_slot_from_round(round)),
        App.globalPut(
            slot.load(),
            update_slot_with_new_vrf_output(
                App.globalGet(slot.load()),
                Sha512_256(vrf_output),
                get_vrf_output_cell_from_round(round)
            )
        )
    ])


@Subroutine(TealType.none)
def verify_and_store_vrf(round: Expr, vrf_proof: Expr, vrf_pk: Expr):
    return store_vrf(
        round,
        verify_vrf(
            round,
            vrf_proof,
            vrf_pk
        )
    )


# init global state with a constant value
@Subroutine(TealType.none)
def init_global_state(start: Expr, length: Expr, round: Expr, vrf_pk: Expr):
    i = ScratchVar(TealType.uint64)
    init = i.store(start)
    cond = i.load() < length
    itr = i.store(i.load() + Int(1))
    return Seq([
        For(init, cond, itr).Do(
            App.globalPut(
                Itob(i.load()),
                Bytes(NB_OF_CELLS_PER_SLOT * HASH_LENGTH * 'a')
                # we need an arbitrary value of length 120 to allow for 3 VRF outputs per slot
            )
        ),
        # store the initial round and the VRF public key in their own slot (metadata slot)
        App.globalPut(Bytes(''), Concat(Itob(round), Itob(round), vrf_pk))
    ])


def get_last_stored_vrf_round():
    return ExtractUint64(App.globalGet(Bytes('')), Int(0))


def get_first_stored_vrf_round():
    return ExtractUint64(App.globalGet(Bytes('')), Int(8))


def get_vrf_pk():
    return Extract(App.globalGet(Bytes('')), Int(16), Int(HASH_LENGTH))


@Subroutine(TealType.uint64)
def is_round_in_valid_range(round: Expr):
    return And(
        get_last_stored_vrf_round() >= round,
        round >= get_first_stored_vrf_round()
    )


@Subroutine(TealType.bytes)
def get_randomness(round: Expr, user_data: Expr):
    return Sha512_256(
        Concat(
            Extract(
                App.globalGet(get_slot_from_round(round)),
                Int(HASH_LENGTH) * get_vrf_output_cell_from_round(round),
                Int(HASH_LENGTH)
            ),
            Itob(round),
            user_data
        )
    )


@Subroutine(TealType.uint64)
def is_recovering(round: Expr):
    return If(
        Global.round() + Int(NB_GRACE_BLOCKS) >= Int(NB_RETAINED_BLOCKS)
    ).Then(
        And(
            Global.round() - get_last_stored_vrf_round() > Int(NB_RETAINED_BLOCKS + SUBMIT_VAL_GAP),
            round % Int(SUBMIT_VAL_GAP) == Int(0),
            round <= ceiling8(Global.round() + Int(NB_GRACE_BLOCKS) - Int(NB_RETAINED_BLOCKS))
        )
    ).Else(
        Int(0)
    )


def can_submit(round: abi.Uint64):
    return Or(
        # Submitting proofs is allowed only for subsequent rounds or in case the smart contract is stalled
        get_last_stored_vrf_round() + Int(SUBMIT_VAL_GAP) == round.get(),
        is_recovering(round.get())
    )


def vrf_beacon_abi():
    router = Router(
        name='Randomness beacon',
        bare_calls=BareCallActions(
            clear_state=OnCompleteAction(action=Approve(), call_config=CallConfig.CALL),
        )
    )

    @router.method(no_op=CallConfig.CREATE)
    def create_app(round: abi.Uint64, vrf_proof: abi.StaticArray[abi.Byte, Literal[80]], vrf_pk: abi.Address):
        return Seq([
            Assert(round.get() % Int(SUBMIT_VAL_GAP) == Int(0)),
            Assert(Len(vrf_pk.get()) == Int(HASH_LENGTH)),
            #  init global state to be bytes
            init_global_state(Int(0), Int(NB_OF_SLOTS), round.get(), vrf_pk.get()),
            # verify the VRF proof and store its output in the correct slot
            verify_and_store_vrf(round.get(), vrf_proof.encode(), vrf_pk.get()),
        ])

    @router.method(no_op=CallConfig.CALL)
    def submit(round: abi.Uint64, vrf_proof: abi.StaticArray[abi.Byte, Literal[80]]):
        return Seq([
            Assert(can_submit(round)),
            # verify the VRF proof and store its output in the correct slot
            verify_and_store_vrf(round.get(), vrf_proof.encode(), get_vrf_pk()),
            # update the last submitted round
            update_last_round(round.get()),
            # update the first submitted round only if recovering or
            If(
                is_recovering(round.get())
            ).Then(
                update_first_round(round.get())
            ).ElseIf(
                get_last_stored_vrf_round() - get_first_stored_vrf_round() >= Int(
                    NB_OF_STORED_VRF_OUTPUTS * SUBMIT_VAL_GAP)
            ).Then(
                update_first_round(get_last_stored_vrf_round() - Int((NB_OF_STORED_VRF_OUTPUTS - 1) * SUBMIT_VAL_GAP))
            )
        ])

    @router.method(no_op=CallConfig.CALL)
    def get(round: abi.Uint64, user_data: abi.DynamicArray[abi.Byte], *,
            output: abi.StaticArray[abi.Byte, Literal[32]]):
        # TODO should we enforce user_data to be of certain minimum length?
        return If(
            Not(is_round_in_valid_range(round.get()))
        ).Then(
            # according to arc-0021, if the requested value can't be found 'get' returns an empty byte slice
            output.decode(
                Bytes('')
            )
        ).Else(
            # if the requested round is in the valid window we return the hash of the concatenation of
            # the VRF output of the requested round with the user input
            output.decode(
                get_randomness(round.get(), user_data.encode())
            )
        )

    @router.method(no_op=CallConfig.CALL)
    def mustGet(round: abi.Uint64, user_data: abi.DynamicArray[abi.Byte], *,
                output: abi.StaticArray[abi.Byte, Literal[32]]):
        # TODO should we enforce user_data to be of certain minimum length?
        return Seq([
            # according to arc-0021, if the requested value can't be found 'mustGet' panics
            Assert(is_round_in_valid_range(round.get())),
            # if the requested round is in the valid window we return the hash of the concatenation of
            # the VRF output of the requested round with the user input
            output.decode(
                get_randomness(round.get(), user_data.encode())
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
