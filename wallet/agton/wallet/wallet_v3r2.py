from __future__ import annotations

from datetime import datetime, timedelta
from dataclasses import dataclass
from typing import Iterable
from itertools import repeat

from agton.ton import Contract, Cell, Message, MessageRelaxed, begin_cell, Provider, TlbConstructor
from agton.ton import Builder, StateInit
from agton.ton import Slice, Address
from agton.ton.types import ActionSendMsg
from agton.ton.crypto.signing import private_key_to_public_key

from agton.wallet.mnemonic import mnemonic_to_private_key, new_mnemonic

WALLET_V3R2_CODE = Cell.from_boc('b5ee9c720101010100710000deff0020dd2082014c97ba218201339cbab19f71b0ed44d0d31fd31f31d70bffe304e0a4f2608308d71820d31fd31fd31ff82313bbf263ed44d0d31fd31fd3ffd15132baf2a15144baf2a204f901541055f910f2a3f8009320d74a96d307d402fb00e8d101a4c8cb1fcb1fcbffc9ed54')
WALLET_V3R2_SUBWALLET_MAGIC = 698983191

@dataclass(frozen=True, slots=True)
class WalletV3R2Data(TlbConstructor):
    seqno: int
    subwallet: int
    public_key: bytes

    @classmethod
    def initial(cls, public_key: bytes, subwallet: int) -> WalletV3R2Data:
        return cls(
            seqno=0,
            subwallet=subwallet,
            public_key=public_key
        )
    
    @classmethod
    def tag(cls):
        return None

    @classmethod
    def deserialize_fields(cls, s: Slice) -> WalletV3R2Data:
        seqno = s.load_uint(32)
        subwallet = s.load_uint(32)
        public_key = s.load_bytes(256 // 8)
        return cls(seqno, subwallet, public_key)

    def serialize_fields(self, b: Builder) -> Builder:
        return (
            b
            .store_uint(self.seqno, 32)
            .store_uint(self.subwallet, 32)
            .store_bytes(self.public_key)
        )


class WalletV3R2(Contract):
    def __init__(self,
                 provider: Provider,
                 address: Address,
                 private_key: bytes,
                 subwallet: int) -> None:
        self.subwallet = subwallet
        self.private_key = private_key
        super().__init__(address, provider)

    def create_signed_external(self, 
                               actions: Iterable[ActionSendMsg],
                               seqno: int | None = None,
                               valid_until: int | None = None,
                               use_dummy_private_key: bool = False,
                               include_state_init: bool = False) -> Message:
        actions = tuple(actions)
        if len(actions) > 4:
            raise ValueError('WalletV3R2 supports only up to 4 messages')
        if valid_until is None:
            t = datetime.now() + timedelta(minutes=3)
            valid_until = int(t.timestamp())
        if seqno is None:
            seqno = self.seqno()
        packed_messages: Builder = Builder()
        for action in actions:
            packed_messages.store_uint(action.mode, 8)
            packed_messages.store_ref(action.out_msg.to_cell())

        unsigned_body = (
            begin_cell()
            .store_uint(self.subwallet, 32)
            .store_uint(valid_until, 32)
            .store_uint(seqno, 32)
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
            data = WalletV3R2Data.initial(public_key, self.subwallet)
            init = StateInit(code=WALLET_V3R2_CODE, data=data.to_cell())
        return self.create_external_message(signed_body, init=init)
    
    def _safety_check(self, mode: int, allow_dangerous: bool):
        if not (mode & 2) and not allow_dangerous:
            raise ValueError(
                'Sending message without SendIgnoreErrors flag set can be dangerous '
                'use alow_dangerous=True if you know what you doing, and want to suppress this error'
            )
    
    def execute(self,
                actions: Iterable[ActionSendMsg],
                seqno: int | None = None,
                valid_until: int | None = None,
                *,
                allow_dangerous: bool = False) -> bytes:
        for action in actions:
            self._safety_check(action.mode, allow_dangerous)
        signed_message = self.create_signed_external(actions, seqno, valid_until)
        return self.send_external_message(signed_message)
    
    def deploy_via_external(self) -> bytes:
        signed_message = self.create_signed_external((),
            seqno=0,
            valid_until=(1 << 32) - 1, 
            include_state_init=True
        )
        return self.send_external_message(signed_message)

    def send(self,
             msg: MessageRelaxed,
             mode: int = 3,
             valid_until: int | None = None,
             *, 
             allow_dangerous: bool = False) -> bytes:
        return self.execute([ActionSendMsg(msg, mode)], valid_until, allow_dangerous=allow_dangerous)

    def seqno(self) -> int:
        s = self.run_get_method('seqno')
        match s:
            case int(): return s
            case _: raise TypeError(f'Unexpected result for seqno: {s!r}')

    @classmethod
    def from_private_key(cls,
                         provider: Provider,
                         private_key: bytes,
                         subwallet: int | None = None,
                         wc: int = 0) -> WalletV3R2:
        if subwallet is None:
            subwallet = WALLET_V3R2_SUBWALLET_MAGIC + wc
        public_key = private_key_to_public_key(private_key)
        data = WalletV3R2Data.initial(public_key, subwallet)
        address = Address.from_state_init(StateInit(
            code=WALLET_V3R2_CODE, 
            data=data.to_cell()
        ), wc)
        return cls(provider, address, private_key, subwallet)

    @classmethod
    def from_mnemonic(cls,
                      provider: Provider,
                      mnemonic: str,
                      subwallet: int | None = None,
                      wc: int = 0) -> WalletV3R2:
        private_key = mnemonic_to_private_key(mnemonic)
        return cls.from_private_key(provider, private_key, subwallet, wc)

    @classmethod
    def create(cls,
               provider: Provider,
               subwallet: int | None = None,
               wc: int = 0) -> tuple[WalletV3R2, str]:
        mnemonic = new_mnemonic()
        return cls.from_mnemonic(provider, mnemonic, subwallet, wc), mnemonic
