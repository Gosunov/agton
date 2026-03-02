from __future__ import annotations

from datetime import datetime, timedelta
from dataclasses import dataclass
from typing import Iterable
from itertools import repeat

from agton.ton import Contract, Cell, Message, MessageRelaxed, begin_cell, Provider, TlbConstructor
from agton.ton import Builder, StateInit
from agton.ton import Slice, Address, HashmapCodec
from agton.ton.types import ActionSendMsg
from agton.ton.crypto.signing import private_key_to_public_key

from agton.wallet.mnemonic import mnemonic_to_private_key, new_mnemonic

WALLET_V4R2_CODE = Cell.from_boc('b5ee9c72010214010002d4000114ff00f4a413f4bcf2c80b010201200203020148040504f8f28308d71820d31fd31fd31f02f823bbf264ed44d0d31fd31fd3fff404d15143baf2a15151baf2a205f901541064f910f2a3f80024a4c8cb1f5240cb1f5230cbff5210f400c9ed54f80f01d30721c0009f6c519320d74a96d307d402fb00e830e021c001e30021c002e30001c0039130e30d03a4c8cb1f12cb1fcbff1011121302e6d001d0d3032171b0925f04e022d749c120925f04e002d31f218210706c7567bd22821064737472bdb0925f05e003fa403020fa4401c8ca07cbffc9d0ed44d0810140d721f404305c810108f40a6fa131b3925f07e005d33fc8258210706c7567ba923830e30d03821064737472ba925f06e30d06070201200809007801fa00f40430f8276f2230500aa121bef2e0508210706c7567831eb17080185004cb0526cf1658fa0219f400cb6917cb1f5260cb3f20c98040fb0006008a5004810108f45930ed44d0810140d720c801cf16f400c9ed540172b08e23821064737472831eb17080185005cb055003cf1623fa0213cb6acb1fcb3fc98040fb00925f03e20201200a0b0059bd242b6f6a2684080a06b90fa0218470d4080847a4937d29910ce6903e9ff9837812801b7810148987159f31840201580c0d0011b8c97ed44d0d70b1f8003db29dfb513420405035c87d010c00b23281f2fff274006040423d029be84c600201200e0f0019adce76a26840206b90eb85ffc00019af1df6a26840106b90eb858fc0006ed207fa00d4d422f90005c8ca0715cbffc9d077748018c8cb05cb0222cf165005fa0214cb6b12ccccc973fb00c84014810108f451f2a7020070810108d718fa00d33fc8542047810108f451f2a782106e6f746570748018c8cb05cb025006cf165004fa0214cb6a12cb1fcb3fc973fb0002006c810108d718fa00d33f305224810108f459f2a782106473747270748018c8cb05cb025005cf165003fa0213cb6acb1f12cb3fc973fb00000af400c9ed54')
WALLET_V4R2_SUBWALLET_MAGIC = 698983191

@dataclass(frozen=True, slots=True)
class WalletV4R2Data(TlbConstructor):
    seqno: int
    subwallet: int
    public_key: bytes
    plugins: set[Address]

    @classmethod
    def initial(cls, public_key: bytes, subwallet: int) -> WalletV4R2Data:
        return cls(
            seqno=0,
            subwallet=subwallet,
            public_key=public_key,
            plugins=set()
        )
    
    @classmethod
    def tag(cls):
        return None

    @classmethod
    def deserialize_fields(cls, s: Slice) -> WalletV4R2Data:
        plugins_codec = HashmapCodec().with_address_keys().with_snake_bytes_values()

        seqno = s.load_uint(32)
        subwallet = s.load_uint(32)
        public_key = s.load_bytes(256 // 8)
        plugins = set(plugins_codec.decode(s.load_hashmap_e(256 + 8)).keys())
        return cls(seqno, subwallet, public_key, plugins)

    def serialize_fields(self, b: Builder) -> Builder:
        plugins_codec = HashmapCodec().with_address_keys().with_snake_bytes_values()
        plugins = plugins_codec.encode({a: b'' for a in self.plugins})
        return (
            b
            .store_uint(self.seqno, 32)
            .store_uint(self.subwallet, 32)
            .store_bytes(self.public_key)
            .store_hashmap_e(plugins, 256 + 8)
        )


class WalletV4R2(Contract):
    def __init__(self,
                 address: Address,
                 private_key: bytes,
                 subwallet: int | None = None,
                 provider: Provider | None = None) -> None:
        if subwallet is None:
            subwallet = WALLET_V4R2_SUBWALLET_MAGIC + address.workchain
        self.subwallet = subwallet
        self.private_key = private_key
        super().__init__(address, provider)

    def create_signed_external(self, 
                               actions: Iterable[ActionSendMsg],
                               valid_until: int,
                               seqno: int,
                               use_dummy_private_key: bool = False,
                               include_state_init: bool = False) -> Message:
        actions = tuple(actions)
        if len(actions) > 4:
            raise ValueError('WalletV4R2 supports only up to 4 messages')
        packed_messages: Builder = Builder()
        for action in actions:
            packed_messages.store_uint(action.mode, 8)
            packed_messages.store_ref(action.out_msg.to_cell())

        unsigned_body = (
            begin_cell()
            .store_uint(self.subwallet, 32)
            .store_uint(valid_until, 32)
            .store_uint(seqno, 32)
            .store_uint(0, 8)
            .store_builder(packed_messages)
        )
        key = bytes([0] * 32) if use_dummy_private_key else self.private_key
        signature = unsigned_body.end_cell().sign(key)
        signed_body = (
            begin_cell()
            .store_bytes(signature)
            .store_builder(unsigned_body)
            .end_cell()
        )
        init = None
        if include_state_init:
            public_key = private_key_to_public_key(self.private_key)
            data = WalletV4R2Data.initial(public_key, self.subwallet)
            init = StateInit(code=WALLET_V4R2_CODE, data=data.to_cell())
        return self.create_external_message(signed_body, init=init)
    
    def _safety_check(self, mode: int, allow_dangerous: bool):
        if not (mode & 2) and not allow_dangerous:
            raise ValueError(
                'Sending message without SendIgnoreErrors flag set can be dangerous'
                'use alow_dangerous=True if you know what you doing, and want to suppress this error'
            )
    
    def execute(self,
                actions: Iterable[ActionSendMsg],
                valid_until: int | None = None,
                *,
                allow_dangerous: bool = False) -> bytes:
        for action in actions:
            self._safety_check(action.mode, allow_dangerous)
        if valid_until is None:
            t = datetime.now() + timedelta(minutes=3)
            valid_until = int(t.timestamp())
        signed_message = self.create_signed_external(actions, valid_until, self.seqno())
        return self.send_external_message(signed_message)
    
    def deploy_via_external(self) -> bytes:
        t = datetime.now() + timedelta(minutes=3)
        valid_until = int(t.timestamp())
        signed_message = self.create_signed_external([], valid_until, 0, include_state_init=True)
        return self.send_external_message(signed_message)

    def send(self,
             msg: MessageRelaxed,
             mode: int = 3,
             valid_until: int | None = None,
             *, 
             allow_dangerous: bool = False) -> bytes:
        return self.execute([ActionSendMsg(msg, mode)], valid_until, allow_dangerous=allow_dangerous)
    
    def send_many(self,
                  msgs: Iterable[MessageRelaxed],
                  modes: Iterable[int] | int = 3,
                  valid_until: int | None = None,
                  *, 
                  allow_dangerous: bool = False) -> bytes:
        if isinstance(modes, int):
            modes = repeat(modes)
            strict = False
        else:
            strict = True
        actions = tuple(
            ActionSendMsg(msg, mode)
            for msg, mode in zip(msgs, modes, strict=strict)
        )
        return self.execute(actions, valid_until, allow_dangerous=allow_dangerous)

    def seqno(self) -> int:
        s = self.run_get_method('seqno')
        match s:
            case int(): return s
            case _: raise TypeError(f'Unexpected result for seqno: {s!r}')

    @classmethod
    def from_private_key(cls,
                         private_key: bytes,
                         subwallet: int | None = None,
                         wc: int = 0,
                         provider: Provider | None = None) -> WalletV4R2:
        if subwallet is None:
            subwallet = WALLET_V4R2_SUBWALLET_MAGIC + wc
        public_key = private_key_to_public_key(private_key)
        data = WalletV4R2Data.initial(public_key, subwallet)
        address = cls.code_and_data_to_address(WALLET_V4R2_CODE, data.to_cell(), wc)
        return cls(address, private_key, subwallet, provider)

    @classmethod
    def from_mnemonic(cls,
                      mnemonic: str,
                      subwallet: int | None = None,
                      wc: int = 0,
                      provider: Provider | None = None) -> WalletV4R2:
        private_key = mnemonic_to_private_key(mnemonic)
        return cls.from_private_key(private_key, subwallet, wc, provider)

    @classmethod
    def create(cls,
               subwallet: int | None = None,
               wc: int = 0,
               provider: Provider | None = None) -> tuple[WalletV4R2, str]:
        mnemonic = new_mnemonic()
        return cls.from_mnemonic(mnemonic, subwallet, wc, provider), mnemonic
