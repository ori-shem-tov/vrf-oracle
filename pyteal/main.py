"""
PyTEAL smart contracts for VRF oracle

See ../DESIGN.md for design details
"""

# pylint: disable=W0401,W0614,E0602
# W0401 is wildcard-import
# W0614 is unused-wildcard-import
# W0622 is redefined-builtin -> due to the fact we need to use "round" as argument for ABI
# E0602 is undefined-variable -> all the types imported from pyteal using *

import json
from typing import Literal

from pyteal import *

# See ../DESIGN.md for definition of indexes, slots, and cells
NB_VRF_SLOTS = 63  # number of slots used to store VRF outputs
NB_VRF_CELLS_PER_SLOT = 3
NB_STORED_VRF_OUTPUTS = NB_VRF_SLOTS * NB_VRF_CELLS_PER_SLOT  # this is also the number of indexes

VRF_ROUND_MULTIPLE = 8  # we only store VRF outputs for rounds that are multiple of this number

# Lengths of the various VRF associated values
VRF_PK_LEN = 32
VRF_PROOF_LEN = 80
STORED_VRF_OUTPUT_LEN = 32  # length of the stored VRF output (that are truncated)

# This part is for the recovery parameters
# In case no VRF proof was submitted for too long, there will be a gap
# in the rounds for which random outputs can be provided
# To get this gap as small as possible, the VRF proof submitter
# is required to submit a VRF proof as old as possible, minus the grace period
# which means submitted round <= current round - NB_RETAINED_BLOCKS + NB_GRACE_BLOCKS
NB_RETAINED_BLOCKS = 1000
NB_GRACE_BLOCKS = 2 * VRF_ROUND_MULTIPLE

# Verify parameters are consistent
# --------------------------------

# Check NB_VRF_CELLS_PER_SLOT stored VRF outputs can fit in a value of global storage with an 8-byte key
assert STORED_VRF_OUTPUT_LEN * NB_VRF_CELLS_PER_SLOT <= 128 - 8


# VRF Rounds, Indexes, Slots, Cells Computation
# =============================================

@Subroutine(TealType.uint64)
def get_vrf_round_from_round(rnd: Expr) -> Expr:
    """
    Return the VRF round used for the given round rnd
    That is the lowest multiple of VRF_ROUND_MULTIPLE
    that is greater or equal to round
    """
    return ((rnd + Int(VRF_ROUND_MULTIPLE - 1)) / Int(VRF_ROUND_MULTIPLE)) * Int(VRF_ROUND_MULTIPLE)


def get_index_from_round(rnd: Expr) -> Expr:
    """
    Return the index in which the VRF output associated to round rnd is stored
    If the round is not a VRF round (i.e., multiple of VRF_ROUND_MULTIPLE), round up to such multiple.
    See ../DESIGN.md for definition of indexes, slots, and cells
    """
    return (get_vrf_round_from_round(rnd) / Int(VRF_ROUND_MULTIPLE)) % Int(NB_STORED_VRF_OUTPUTS)


@Subroutine(TealType.uint64)
def get_slot_from_round(rnd: Expr) -> Expr:
    """
    Return the slot number in which the VRF output associated to round rnd is stored
    If the round is not a VRF round (i.e., multiple of VRF_ROUND_MULTIPLE), round up to such multiple.
    See ../DESIGN.md for definition of indexes, slots, and cells
    """
    return get_index_from_round(rnd) / Int(NB_VRF_CELLS_PER_SLOT)


@Subroutine(TealType.uint64)
def get_cell_from_round(rnd: Expr) -> Expr:
    """
    Return the cell number (within the slot_ in which the VRF output associated to round rnd is stored
    If the round is not a VRF round (i.e., multiple of VRF_ROUND_MULTIPLE), round up to such multiple.
    See ../DESIGN.md for definition of indexes, slots, and cells
    """
    return get_index_from_round(rnd) % Int(NB_VRF_CELLS_PER_SLOT)


# ============================
#
# Application State Read/Write
#
# ============================

# Note: most of these functions are not subroutines
#       as they are too simple and making them subroutine would be inefficient

# Main slot
# Key = Byte("")
# Value = last_round | first_round | vrf_pk

def get_last_round_stored() -> Expr:
    """
    Return the last round stored in the application state (main slot)
    """
    return ExtractUint64(App.globalGet(Bytes('')), Int(0))


def put_last_round_stored(last_round: Expr) -> Expr:
    """
    Update the last round in the application state (main slot)
    """
    return App.globalPut(
        Bytes(''),
        Concat(
            Itob(last_round),
            Itob(get_first_round_stored()),
            get_vrf_pk()
        )
    )


def get_first_round_stored() -> Expr:
    """
    Return the first round stored in the application state (main slot)
    """
    return ExtractUint64(App.globalGet(Bytes('')), Int(8))


def put_first_round_stored(first_round: Expr) -> Expr:
    """
    Update the first round in the application state (main slot)
    """
    return App.globalPut(
        Bytes(''),
        Concat(
            Itob(get_last_round_stored()),
            Itob(first_round),
            get_vrf_pk()
        )
    )


def get_vrf_pk() -> Expr:
    """
    Return the VRF pk stored in the application state (main slot)
    """
    return Extract(App.globalGet(Bytes('')), Int(16), Int(VRF_PK_LEN))


def get_stored_vrf_output(rnd: Expr) -> Expr:
    """
    Return the stored (truncated) VRF output for the round rnd
    If rnd is not a multiple of VRF_ROUND_MULTIPLE, then round up to such a multiple
    Assumes the round is valid (that is the VRF output for the corresponding round is actually stored).
    This can be checked with is_round_in_valid_range
    """
    return Extract(
        App.globalGet(Itob(get_slot_from_round(rnd))),
        Int(STORED_VRF_OUTPUT_LEN) * get_cell_from_round(rnd),
        Int(STORED_VRF_OUTPUT_LEN)
    )


@Subroutine(TealType.none)
def put_stored_vrf_output(rnd: Expr, truncated_vrf_output: Expr):
    """
    Store the (truncated) VRF output in its designated cell
    Does not change the other stored VRF outputs.
    """
    slot = ScratchVar(TealType.bytes)
    return Seq([
        Assert(Len(truncated_vrf_output) == Int(STORED_VRF_OUTPUT_LEN)),
        slot.store(Itob(get_slot_from_round(rnd))),
        App.globalPut(
            slot.load(),
            update_slot_with_new_vrf_output(
                App.globalGet(slot.load()),
                truncated_vrf_output,
                get_cell_from_round(rnd)
            )
        )
    ])


@Subroutine(TealType.bytes)
def update_slot_with_new_vrf_output(slot: Expr, truncated_vrf_output: Expr, vrf_output_cell_idx: Expr):
    """
    Return the slot value where the vrf_output_cell_idx's cell content
    has been replaced by truncated_vrf_output
    and the other cells are kept the same

    Auxiliary function for put_stored_vrf_output
    Assumes truncated_vrf_output to be STORED_VRF_OUTPUT-byte long
    """
    first = Concat(
        truncated_vrf_output,
        Extract(slot, Int(STORED_VRF_OUTPUT_LEN), Int(2 * STORED_VRF_OUTPUT_LEN))
    )
    second = Concat(
        Extract(slot, Int(0), Int(STORED_VRF_OUTPUT_LEN)),
        truncated_vrf_output,
        Extract(slot, Int(2 * STORED_VRF_OUTPUT_LEN), Int(STORED_VRF_OUTPUT_LEN))
    )
    third = Concat(
        Extract(slot, Int(0), Int(2 * STORED_VRF_OUTPUT_LEN)),
        truncated_vrf_output
    )
    return Cond(
        [vrf_output_cell_idx == Int(0), first],
        [vrf_output_cell_idx == Int(1), second],
        [vrf_output_cell_idx == Int(2), third],
    )


# ============================================================================
#
# Cryptography-related routines: VRF verification and random output generation
#
# ============================================================================


@Subroutine(TealType.bytes)
def verify_vrf(rnd: Expr, vrf_proof: Expr, vrf_pk: Expr):
    """
    Verify the VRF proof and returns the truncated VRF output if valid.
    (Truncation is done so the output length is STORED_VRF_OUTPUT_LEN.)
    Panic if the vrf_proof is invalid
    """
    block_seed = Block.seed(rnd)  # this panics if seed is unavailable, which is what we want
    vrf_verify = VrfVerify.algorand(Sha512_256(Concat(Itob(rnd), block_seed)), vrf_proof, vrf_pk)
    return Seq([
        vrf_verify,
        Assert(vrf_verify.output_slots[1].load() == Int(1)),  # verify the VRF proof is valid
        Extract(vrf_verify.output_slots[0].load(), Int(0), Int(STORED_VRF_OUTPUT_LEN))  # return truncated VRF output
    ])


@Subroutine(TealType.none)
def verify_and_store_vrf(rnd: Expr, vrf_proof: Expr, vrf_pk: Expr):
    """
    Verify the VRF proof and store the VRF output in the right place
    Assumes that round rnd is already a multiple of VRF_ROUND_MULTIPLE
    """
    return put_stored_vrf_output(
        rnd,
        verify_vrf(
            rnd,
            vrf_proof,
            vrf_pk
        )
    )


@Subroutine(TealType.bytes)
def get_random_output(rnd: Expr, user_data: Expr):
    """
    Get the random output associated with round rnd and user_data
    It assumes that round is valid (checked using is_round_in_valid_range)
    """
    return Sha3_256(
        Concat(
            get_stored_vrf_output(rnd),
            Itob(rnd),
            user_data
        )
    )


# ==================================
#
# Misc Subroutines (init and checks)
#
# ==================================


# init global state with a constant value
@Subroutine(TealType.none)
def init_global_state(rnd: Expr, vrf_pk: Expr):
    """
    Initialize the global state
    """
    i = ScratchVar(TealType.uint64)
    init = i.store(Int(0))
    cond = i.load() < Int(NB_VRF_SLOTS)
    itr = i.store(i.load() + Int(1))
    return Seq([
        # store an arbitrary value in each of the VRF slots
        For(init, cond, itr).Do(
            App.globalPut(
                Itob(i.load()),
                Bytes(NB_VRF_CELLS_PER_SLOT * STORED_VRF_OUTPUT_LEN * 'a')
                # we need an arbitrary value of the right length to allow for 3 VRF outputs per slot
            )
        ),
        # store the initial round and the VRF public key in the main slot
        App.globalPut(Bytes(''), Concat(Itob(rnd), Itob(rnd), vrf_pk))
    ])


@Subroutine(TealType.uint64)
def is_round_in_valid_range(rnd: Expr):
    """
    Return whether a round rnd is in the valid range to get associated random output.
    I.e., its associated VRF round is between the first and last round stored.
    """
    vrf_round = get_vrf_round_from_round(rnd)
    return And(
        vrf_round <= get_last_round_stored(),
        vrf_round >= get_first_round_stored()
    )


@Subroutine(TealType.uint64)
def is_valid_recovering_round(rnd: Expr):
    """
    Return whether the round rnd provided is allowed to be submitted by the VRF service
    AND corresponds to a recovering round
    """
    return And(
        # rounds must be multiple of VRF_ROUND_MULTIPLE
        rnd % Int(VRF_ROUND_MULTIPLE) == Int(0),
        # there is a gap between expected next VRF round and provided VRF round => we are in recovery
        rnd > get_last_round_stored() + Int(VRF_ROUND_MULTIPLE),
        # the round provided is as early as possible bare the grace period
        (rnd + Int(NB_RETAINED_BLOCKS)) <= (Global.round() + Int(NB_GRACE_BLOCKS))
    )


def can_submit(rnd: Expr):
    """
    Return whether the VRF service can submit a VRF proof for the round rnd.

    Submitting proofs is allowed only for the following VRF round (last round + VRF_ROUND_MULTIPLE)
    OR when we're recovering
    """
    return Or(
        get_last_round_stored() + Int(VRF_ROUND_MULTIPLE) == rnd,
        is_valid_recovering_round(rnd)
    )


# ==============================
#
# ABI-Compliant Main Application
#
# ==============================


def vrf_beacon_abi():
    """
    ABI-Compliant Main Application
    """
    router = Router(
        name='Randomness beacon',
        bare_calls=BareCallActions(
            clear_state=OnCompleteAction(action=Approve(), call_config=CallConfig.CALL),
        )
    )

    @router.method(no_op=CallConfig.CREATE)
    def create_app(
            round: abi.Uint64,  # pylint: disable=W0622
            vrf_proof: abi.StaticBytes[Literal[VRF_PROOF_LEN]],
            vrf_pk: abi.StaticBytes[Literal[VRF_PK_LEN]]
    ):
        # Since no_op=CallConfig.CREATE, this call can only be made at application creation.
        # This is very important, otherwise anyone could reset the beacon VRF and that would be insecure!
        return Seq([
            # it is very important we check we are a multiple of VRF_ROUND_MULTIPLE here
            # otherwise we may be forever shifted
            Assert(round.get() % Int(VRF_ROUND_MULTIPLE) == Int(0)),
            Assert(Len(vrf_pk.get()) == Int(VRF_PK_LEN)),
            # init global state
            init_global_state(round.get(), vrf_pk.get()),
            # verify the VRF proof and store its output in the correct slot
            verify_and_store_vrf(round.get(), vrf_proof.get(), vrf_pk.get()),
        ])

    @router.method(no_op=CallConfig.CALL)
    def submit(
            round: abi.Uint64,  # pylint: disable=W0622
            vrf_proof: abi.StaticBytes[Literal[VRF_PROOF_LEN]]
    ):
        # Note that anyone can call this function, which is what we want.
        # In case the account used by the VRF service gets compromised, the VRF service can switch to a new one
        # completely seamlessly.
        is_recovering = ScratchVar(TealType.uint64)
        return Seq([
            # verify this block can be submitted
            Assert(can_submit(round.get())),
            # store whether we are in recovery mode or not
            # note that this is important to store it there, because updates to last round makes it no more in recovery
            is_recovering.store(is_valid_recovering_round(round.get())),
            # verify the VRF proof and store its output in the correct slot/cell
            verify_and_store_vrf(round.get(), vrf_proof.get(), get_vrf_pk()),
            # update the last submitted round
            put_last_round_stored(round.get()),
            # update the first submitted round
            If(
                is_recovering.load()
            ).Then(
                # if recovering, now the current round is the first round
                put_first_round_stored(round.get())
            ).ElseIf(
                get_last_round_stored() - get_first_round_stored() >= Int(NB_STORED_VRF_OUTPUTS * VRF_ROUND_MULTIPLE)
            ).Then(
                # update the first round to the earliest first round stored
                # which must be larger than last_round - NB_STORED_VRF_OUTPUT * VRF_ROUND_MULTIPLE
                # (the round last_round - NB_STORED_VRF_OUTPUT * VRF_ROUND_MULTIPLE was indeed
                #  overwritten by the last VRF output)
                put_first_round_stored(
                    get_last_round_stored() - Int((NB_STORED_VRF_OUTPUTS - 1) * VRF_ROUND_MULTIPLE)
                )
            )
        ])

    @router.method(no_op=CallConfig.CALL)
    def get(
            round: abi.Uint64,  # pylint: disable=W0622
            user_data: abi.DynamicBytes,
            *,
            output: abi.DynamicBytes
    ):
        return If(
            Not(is_round_in_valid_range(round.get()))
        ).Then(
            # according to arc-0021, if the requested value can't be found 'get' returns an empty byte slice
            output.set(
                Bytes('')
            )
        ).Else(
            # if the requested round is in the valid window we return the hash of the concatenation of
            # the VRF output of the requested round with the user input
            output.set(
                get_random_output(round.get(), user_data.get())
            )
        )

    @router.method(no_op=CallConfig.CALL)
    def must_get(
            round: abi.Uint64,  # pylint: disable=W0622
            user_data: abi.DynamicBytes,
            *,
            output: abi.DynamicBytes
    ):
        return Seq([
            # according to arc-0021, if the requested value can't be found 'must_get' panics
            Assert(is_round_in_valid_range(round.get())),
            # if the requested round is in the valid window we return the hash of the concatenation of
            # the VRF output of the requested round with the user input
            output.set(
                get_random_output(round.get(), user_data.get())
            )
        ])

    return router


if __name__ == '__main__':
    # this will immediately fail if the current PyTeal version does not satisfy the
    # version constraint
    pragma(compiler_version="0.17.0")
    compiled, clear, contract = vrf_beacon_abi().compile_program(version=7)

    file_name = 'vrf_beacon_abi_approval.teal'  # pylint: disable = C0103
    with open(file_name, 'w', encoding='utf8') as f:
        f.write(compiled)
        print(f'compiled {file_name}')

    file_name = 'vrf_beacon_abi_clear.teal'  # pylint: disable = C0103
    with open(file_name, 'w', encoding='utf8') as f:
        f.write(clear)
        print(f'compiled {file_name}')

    file_name = 'contract.json'  # pylint: disable = C0103
    with open(file_name, 'w', encoding='utf8') as f:
        print(json.dumps(contract.dictify(), indent=4), file=f)
        print(f'compiled {file_name}')

    DUMMY_APP_APPROVAL = compileTeal(Txn.on_completion() == OnComplete.NoOp, mode=Mode.Application, version=7)
    file_name = 'dummy_app_approval.teal'  # pylint: disable = C0103
    with open(file_name, 'w', encoding='utf8') as f:
        f.write(DUMMY_APP_APPROVAL)
        print(f'compiled {file_name}')

    DUMMY_APP_CLEAR = compileTeal(Int(1), mode=Mode.Application, version=7)
    file_name = 'dummy_app_clear.teal'  # pylint: disable = C0103
    with open(file_name, 'w', encoding='utf8') as f:
        f.write(DUMMY_APP_CLEAR)
        print(f'compiled {file_name}')
