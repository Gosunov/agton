from __future__ import annotations

from datetime import datetime, timedelta
from dataclasses import dataclass
from typing import Iterable
from itertools import repeat

from agton.ton import Contract, StateInit, Cell, Message, MessageRelaxed, begin_cell, Provider, TlbConstructor
from agton.ton import Builder
from agton.ton import Slice, Address
from agton.ton.crypto.signing import private_key_to_public_key
from agton.ton.types import ActionSendMsg, OutList, OutListCons, OutListEmpty, out_list

from agton.wallet.mnemonic import mnemonic_to_private_key, new_mnemonic

PREPROCESSED_WALLET_V2_CODE = Cell.from_boc('B5EE9C7241010101003D000076FF00DDD40120F90001D0D33FD30FD74CED44D0D3FFD70B0F20A4830FA90822C8CBFFCB0FC9ED5444301046BAF2A1F823BEF2A2F910F2A3F800ED552E766412')

@dataclass(frozen=True, slots=True)
class PreprocessedWalletData(TlbConstructor):
    public_key: bytes
    seqno: int

    @classmethod
    def initial(cls, public_key: bytes) -> PreprocessedWalletData:
        return cls(
            public_key=public_key,
            seqno=0
        )
    
    @classmethod
    def tag(cls):
        return None

    @classmethod
    def deserialize_fields(cls, s: Slice) -> PreprocessedWalletData:
        public_key = s.load_bytes(256 // 8)
        seqno = s.load_uint(16)
        return cls(public_key, seqno)

    def serialize_fields(self, b: Builder) -> Builder:
        return (
            b
            .store_bytes(self.public_key)
            .store_uint(self.seqno, 16)
        )


class PreprocessedWalletV2(Contract):
    def __init__(self,
                 address: Address,
                 private_key: bytes,
                 provider: Provider | None = None) -> None:
        self.private_key = private_key
        super().__init__(address, provider)

    def create_signed_external(self, 
                               actions: Iterable[ActionSendMsg],
                               valid_until: int,
                               seqno: int,
                               use_dummy_private_key: bool = False,
                               include_state_init: bool = False) -> Message:
        actions = tuple(actions)
        if len(actions) > 255:
            raise ValueError('WalletV3R2 supports only up to 255 messages')
        out_msgs = OutListEmpty()
        for action in actions:
            out_msgs = OutListCons(out_msgs, action)

        inner_msg = (
            begin_cell()
            .store_uint(valid_until, 64)
            .store_uint(seqno, 16)
            .store_ref_tlb(out_msgs)
            .end_cell()
        )
        key = bytes([0] * 32) if use_dummy_private_key else self.private_key
        signature = inner_msg.sign(key)
        signed_body = (
            begin_cell()
            .store_bytes(signature)
            .store_ref(inner_msg)
            .end_cell()
        )
        init = None
        if include_state_init:
            public_key = private_key_to_public_key(self.private_key)
            data = PreprocessedWalletData.initial(public_key)
            init = StateInit(code=PREPROCESSED_WALLET_V2_CODE, data=data.to_cell())
        return self.create_external_message(signed_body, init=init)
    
    def _safety_check(self, mode: int, allow_dangerous: bool):
        if not (mode & 2) and not allow_dangerous:
            raise ValueError(
                'Sending message without SendIgnoreErrors flag set can be dangerous'
                'use alow_dangerous=True if you know what you doing, and want to suppress this error'
            )
    
    def execute(self,
                actions: Iterable[ActionSendMsg],
                seqno: int,
                valid_until: int | None = None,
                *,
                allow_dangerous: bool = False) -> bytes:
        for action in actions:
            self._safety_check(action.mode, allow_dangerous)
        if valid_until is None:
            t = datetime.now() + timedelta(minutes=50)
            valid_until = int(t.timestamp())
        signed_message = self.create_signed_external(actions, valid_until, seqno)
        return self.send_external_message(signed_message)
    
    def deploy_via_external(self) -> bytes:
        t = datetime.now() + timedelta(minutes=3)
        valid_until = int(t.timestamp())
        signed_message = self.create_signed_external([], valid_until, 0, include_state_init=True)
        return self.send_external_message(signed_message)

    def send(self,
             seqno: int,
             msg: MessageRelaxed,
             mode: int = 3,
             valid_until: int | None = None,
             *, 
             allow_dangerous: bool = False) -> bytes:
        return self.execute([ActionSendMsg(msg, mode)], seqno, valid_until, allow_dangerous=allow_dangerous)
    
    def send_many(self,
                  seqno: int,
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
        return self.execute(actions, seqno, valid_until, allow_dangerous=allow_dangerous)

    @classmethod
    def from_private_key(cls,
                         private_key: bytes,
                         wc: int = 0,
                         provider: Provider | None = None) -> PreprocessedWalletV2:
        public_key = private_key_to_public_key(private_key)
        data = PreprocessedWalletData.initial(public_key)
        address = Address.from_state_init(StateInit(
            code=PREPROCESSED_WALLET_V2_CODE, 
            data=data.to_cell()
        ), wc)
        return cls(address, private_key, provider)

    @classmethod
    def from_mnemonic(cls,
                      mnemonic: str,
                      wc: int = 0,
                      provider: Provider | None = None) -> PreprocessedWalletV2:
        private_key = mnemonic_to_private_key(mnemonic)
        return cls.from_private_key(private_key, wc, provider)

    @classmethod
    def create(cls,
               wc: int = 0,
               provider: Provider | None = None) -> tuple[PreprocessedWalletV2, str]:
        mnemonic = new_mnemonic()
        return cls.from_mnemonic(mnemonic, wc, provider), mnemonic
