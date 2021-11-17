import os

from Cryptodome.Hash import SHA512
from pyteal import *
from algosdk import encoding
from algosdk.v2client import algod
from base64 import b32encode, b64encode, b64decode


def game_stateless_escrow(addr_a: str, addr_b: str, counter: str):
    handle_query_phase = And(
        Bytes('base16', counter) == Bytes('base16', counter),
        Txn.rekey_to() == Global.zero_address(),
        Global.group_size() == Int(4),
        *[And(
            Gtxn[i].type_enum() == TxnType.Payment,
            Gtxn[i].sender() == Addr(addr),
            Gtxn[i].receiver() == Txn.sender(),
        ) for i, addr in enumerate([addr_a, addr_b])],
        Or(
            And(
                Txn.group_index() == Int(2),
                Txn.type_enum() == TxnType.ApplicationCall,
                Txn.on_completion() == OnComplete.OptIn,
            ),
            And(
                Txn.group_index() == Int(3),
                Txn.type_enum() == TxnType.Payment,
                Txn.close_remainder_to() == Global.zero_address(),
            )
        )
    )

    handle_settlement_phase = Cond(
        [Global.group_size() != Int(2), Return(Int(0))],
        [
            Txn.group_index() == Int(0),
            Return(
                And(
                    Txn.type_enum() == TxnType.ApplicationCall,
                    Txn.on_completion() == OnComplete.CloseOut,
                )
            )
        ],
        [
            Txn.group_index() == Int(1),
            Return(
                And(
                    Txn.type_enum() == TxnType.Payment,
                    Txn.amount() == Int(0),
                    Gtxn[0].type_enum() == TxnType.ApplicationCall,
                    Gtxn[0].on_completion() == OnComplete.CloseOut,
                    Or(
                        And(
                            Gtxn[0].application_args[0] == Bytes('A'),
                            Txn.close_remainder_to() == Addr(addr_a),
                        ),
                        And(
                            Gtxn[0].application_args[0] == Bytes('B'),
                            Txn.close_remainder_to() == Addr(addr_b),
                        ),
                    )
                )
            )
        ],
    )

    return Cond(
        [Arg(0) == Bytes('query'), Return(handle_query_phase)],
        [Arg(0) == Bytes('settlement'), handle_settlement_phase],
    )


def oracle_stateless_escrow(signing_pk_b32: str, owner_address: str, sender: str, block: str, x_b32: str, app_id: int, arg0: str):
    return Cond(
        [Global.group_size() != Int(2), Return(Int(0))],
        [
            Txn.group_index() == Int(0),
            Return(
                And(
                    Txn.type_enum() == TxnType.ApplicationCall,
                    Txn.application_id() == Btoi(Bytes('base16', f'0x{app_id:016x}')),
                    Txn.application_args[0] == Bytes(arg0),
                    Txn.application_args[1] == Bytes(block),
                    Txn.application_args[3] == Bytes('base32', x_b32),
                    Txn.accounts[1] == Addr(sender),
                    Ed25519Verify(
                        Concat(
                            Txn.sender(),
                            Bytes(block),
                            Txn.application_args[2],
                            Bytes('base32', x_b32),
                            Txn.application_args[4]
                        ),
                        Arg(0),
                        Bytes('base32', signing_pk_b32)
                    )
                )
            ),
        ],
        [
            Txn.group_index() == Int(1),
            Return(
                And(
                    Txn.type_enum() == TxnType.Payment,
                    Txn.amount() == Int(0),
                    Txn.close_remainder_to() == Addr(owner_address)
                )
            )
        ]
    )


def game_stateful_app(eabc_prefix_b64: str, eabc_suffix_hash_b64: str, oracle_signing_pk_b32: str, oracle_owner_address: str, oe_prefix_b64: str, oe_suffix_hash_b64: str):
    eabc_logic = Concat(
        Bytes('Program'),
        Bytes('base64', eabc_prefix_b64),
        Bytes('base16', '0x01'),
        Bytes('A'),
        Bytes('base16', '0x20'),
        Txn.application_args[0],
        Bytes('base16', '0x01'),
        Bytes('B'),
        Bytes('base16', '0x20'),
        Txn.application_args[1],
        Bytes('base16', '0x08'),
        Txn.application_args[2],
        Txn.application_args[5],
    )
    eabc_addr = Sha512_256(eabc_logic)
    validate_eabc_suffix = Sha512_256(Txn.application_args[5]) == Bytes('base64', eabc_suffix_hash_b64)
    validate_eabc = And(validate_eabc_suffix, Txn.sender() == eabc_addr)
    handle_opt_in = Seq(
        [
            If(Not(validate_eabc), Return(Int(0))),
            App.localPut(Int(0), Bytes('A'), Txn.application_args[0]),
            App.localPut(Int(0), Bytes('B'), Txn.application_args[1]),
            App.localPut(Int(0), Bytes('counter'), Txn.application_args[2]),
            App.localPut(Int(0), Bytes('block'), Txn.application_args[3]),
            App.localPut(Int(0), Bytes('expiration'), Txn.application_args[4]),
            Int(1),
        ]
    )
    oe_logic = Concat(
        Bytes('Program'),
        Bytes('base64', oe_prefix_b64),
        Bytes('base16', '0x20'),
        Addr(oracle_owner_address),
        Bytes('base16', '0x08'),
        Itob(App.id()),
        Bytes('base16', '0x03'),
        Bytes('vrf'),
        Bytes('base16', '0x08'),
        App.localGet(Int(1), Bytes('block')),
        Bytes('base16', '0x20'),
        Sha512_256(Concat(App.localGet(Int(1), Bytes('A')), App.localGet(Int(1), Bytes('B')), App.localGet(Int(1), Bytes('counter')))),
        Bytes('base16', '0x20'),
        Txn.accounts[1],
        Bytes('base16', '0x20'),
        Bytes('base32', oracle_signing_pk_b32),
        Txn.application_args[6],
    )
    oe_addr = Sha512_256(oe_logic)
    validate_oe_suffix = Sha512_256(Txn.application_args[6]) == Bytes('base64', oe_suffix_hash_b64)
    validate_oe = And(validate_oe_suffix, Txn.sender() == oe_addr)
    store_vrf = Seq(
        [
            If(Not(validate_oe), Return(Int(0))),
            App.localPut(Int(1), Bytes('vrf'), Txn.application_args[4]),
            Int(1),
        ]
    )
    vrf_suffix = Btoi(Substring(App.localGet(Int(0), Bytes('vrf')), Int(63), Int(64)))
    handle_close_out = Or(
        And(
            vrf_suffix % Int(2) == Int(0),
            Txn.application_args[0] == Bytes('A')
        ),
        And(
            vrf_suffix % Int(2) == Int(1),
            Txn.application_args[0] == Bytes('B')
        )
    )
    program = Cond(
        [Txn.application_id() == Int(0), Return(Int(1))],
        [Txn.on_completion() == OnComplete.DeleteApplication, Return(Int(1))],
        [Txn.on_completion() == OnComplete.OptIn, Return(handle_opt_in)],
        [Txn.on_completion() == OnComplete.CloseOut, Return(handle_close_out)],
        [Txn.application_args[0] == Bytes('vrf'), Return(store_vrf)]
    )
    return program


def game_clear_out():
    program = Seq([
        Return(Int(1))
    ])
    return program


def cut(prog: bytes, prefix_end: int, suffix_start: int):
    prefix = prog[:prefix_end]
    suffix = prog[suffix_start:]
    prefix_b64 = b64encode(prefix)
    suffix_b64 = b64encode(suffix)
    checksum = SHA512.new(truncate='256')
    checksum.update(suffix)
    suffix_hash_b64 = b64encode(checksum.digest())
    return prefix_b64.decode(), suffix_b64.decode(), suffix_hash_b64.decode()


if __name__ == '__main__':
    algod_addr = os.getenv('AF_ALGOD_ADDRESS')
    algod_token = os.getenv('AF_ALGOD_TOKEN')
    if algod_addr == '':
        print('please export AF_ALGOD_ADDRESS and AF_ALGOD_TOKEN environment variables to a valid v2 algod client')
        exit(1)
    algod_client = algod.AlgodClient(
        algod_token,
        algod_addr,
    )

    A = 'USBW2XJGOJINHTAJJPKXV3S2NWSZKV4KRWH5KIBOZYUTKFNXP73WSZITGI'
    B = 'ZUUCQCF3AVUBLFOSRSN6NY64GI3ZI2XJJ53ONX7EM7DJBWXYIXQB3UAMFU'
    counter = 'AAAAAAAAAAAAAAAA'
    oracle_pk_addr = 'YUO5WDTSKVI5VADGDNGDCFDTPDO2TQMH2OZGZ6MLDXA6G2ZU5CD5GWVHBE'
    oracle_pk = b32encode(encoding.decode_address(oracle_pk_addr)).decode()
    oracle_owner_addr = 'LI5I7DNXC2FK6EVUJUOKXIPS3LV7FU5VHHI7LHBRIEBTTEWX5GICA47DBQ'
    block_number = 50
    app_id = 6
    x = SHA512.new(data=encoding.decode_address(A) + encoding.decode_address(B) + bytes.fromhex(counter),
                   truncate='256').digest()
    x_b32 = b32encode(x).decode()
    eabc_prefix_b64 = 'AyAGAgABBgQDJgcFcXVlcnkKc2V0dGxlbWVudA=='
    eabc_suffix_hash_b64 = 'LrNN6J2dT3lNiyWURbFtGON6hBX+spjIchpqzXDa50Y='
    oe_prefix_b64 = 'AyAEAgABBiYH'
    oe_suffix_hash_b64 = 'zEZzhDSiWe2/QmPpKlJQBn0uftoy9D7P4Vp3jE2qE9k='

    filename = 'game_stateless_escrow.teal'
    with open(filename, 'w') as f:
        compiled = compileTeal(
            game_stateless_escrow(A, B, counter),
            Mode.Signature, version=3
        )
        f.write(compiled)
        print(f'compiled {filename}')
        try:
            res = algod_client.compile(compiled)
        except Exception as e:
            print(f'error compiling stateless TEAL {e}')
            exit(1)

    eabc_addr = res['hash']
    eabc_logic = b64decode(res['result'])
    print(f'eabc addr: {eabc_addr}')
    eabc_prefix_b64, eabc_suffix_b64, eabc_suffix_hash_b64 = cut(eabc_logic, 28, 107)
    print(f'eabc_prefix_b64: {eabc_prefix_b64}, eabc_suffix_b64: {eabc_suffix_b64}, eabc_suffix_hash_b64: {eabc_suffix_hash_b64}')

    filename = 'oracle_stateless_escrow.teal'
    with open(filename, 'w') as f:
        compiled = compileTeal(
            oracle_stateless_escrow(
                oracle_pk,
                oracle_owner_addr,
                eabc_addr,
                f'{block_number:08}',
                x_b32,
                app_id,
                "vrf"
            ),
            Mode.Signature, version=3
        )
        f.write(compiled)
        print(f'compiled {filename}')

        try:
            res = algod_client.compile(compiled)
        except Exception as e:
            print(f'error compiling stateless TEAL {e}')
            exit(1)

    oe_addr = res['hash']
    print(f'oe addr: {oe_addr}')

    filename = 'game_stateful_app.teal'
    with open(filename, 'w') as f:
        compiled = compileTeal(game_stateful_app(eabc_prefix_b64, eabc_suffix_hash_b64, oracle_pk, oracle_owner_addr, oe_prefix_b64, oe_suffix_hash_b64), Mode.Application, version=3)
        f.write(compiled)
        print(f'compiled {filename}')

    filename = 'game_clear_out.teal'
    with open(filename, 'w') as f:
        compiled = compileTeal(game_clear_out(), Mode.Application, version=3)
        f.write(compiled)
        print(f'compiled {filename}')

    filename = 'test.teal'
    with open(filename, 'w') as f:
        compiled = compileTeal(
            If(
                Txn.application_id() != Int(0),
                ScratchVar().store(
                    Concat(
                        Bytes('Program'),
                        Bytes('base64', oe_prefix_b64),
                        Bytes('base16', '0x20'),
                        Addr(oracle_owner_addr),
                        Bytes('base16', '0x08'),
                        Itob(Txn.application_id()),
                        Bytes('base16', '0x03'),
                        Bytes('vrf'),
                        Bytes('base16', '0x08'),
                        Txn.application_args[3],
                        Bytes('base16', '0x20'),
                        Sha256(Concat(Txn.application_args[0], Txn.application_args[1],
                                      Txn.application_args[2])),
                        Bytes('base16', '0x20'),
                        Txn.accounts[1],
                        Bytes('base16', '0x20'),
                        Bytes('base32', oracle_pk),
                        Txn.application_args[4],
                    )
                ), Return(Int(1))
            ),
            Mode.Application,
            version=3,
        )
        f.write(compiled)
        print(f'compiled {filename}')
