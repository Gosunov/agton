from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from agton.ton import Contract, Cell, Message, MessageRelaxed, begin_cell, Provider, TlbConstructor
from agton.ton import Builder
from agton.ton import Slice, Address
from agton.ton.crypto.signing import private_key_to_public_key

from agton.wallet.mnemonic import mnemonic_to_private_key, new_mnemonic

WALLET_V1R3_CODE = Cell.from_boc('b5ee9c7201010101005f0000baff0020dd2082014c97ba218201339cbab19c71b0ed44d0d31fd70bffe304e0a4f260810200d71820d70b1fed44d0d31fd3ffd15112baf2a122f901541044f910f2a2f80001d31f3120d74a96d307d402fb00ded1a4c8cb1fcbffc9ed54')

@dataclass(frozen=True, slots=True)
class WalletV1R3Data(TlbConstructor):
    seqno: int
    public_key: bytes

    @classmethod
    def initial(cls, public_key: bytes) -> WalletV1R3Data:
        return cls(
            seqno=0,
            public_key=public_key
        )
    
    @classmethod
    def tag(cls):
        return None

    @classmethod
    def deserialize_fields(cls, s: Slice) -> WalletV1R3Data:
        seqno = s.load_uint(32)
        public_key = s.load_bytes(256 // 8)
        return cls(seqno, public_key)

    def serialize_fields(self, b: Builder) -> Builder:
        return (
            b
            .store_uint(self.seqno, 32)
            .store_bytes(self.public_key)
        )


class WalletV1R3(Contract):
    def __init__(self,
                 address: Address,
                 private_key: bytes,
                 provider: Provider | None = None) -> None:
        self.private_key = private_key
        super().__init__(address, provider)

    MessageWithMode = tuple[MessageRelaxed, int]

    def create_signed_external(self, 
                               messages_with_modes: Iterable[MessageWithMode],
                               seqno: int,
                               use_dummy_private_key: bool = False) -> Message:
        messages_with_modes = tuple(messages_with_modes)
        if len(messages_with_modes) > 4:
            raise ValueError('WalletV3R2 supports only up to 4 messages')
        packed_messages: Builder = Builder()
        for message, mode in messages_with_modes:
            packed_messages.store_uint(mode, 8)
            packed_messages.store_ref(message.to_cell())

        unsigned_body = (
            begin_cell()
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
        return self.create_external_message(signed_body)
    
    def _safety_check(self, mode: int, allow_dangerous: bool):
        if not (mode & 2) and not allow_dangerous:
            raise ValueError(
                'Sending message without SendIgnoreErrors flag set can be dangerous'
                'use alow_dangerous=True if you know what you doing, and want to suppress this error'
            )

    def send(self,
             m: MessageRelaxed,
             mode: int = 3,
             *, 
             allow_dangerous: bool = False) -> bytes:
        self._safety_check(mode, allow_dangerous)
        signed_message = self.create_signed_external([(m, mode)], self.seqno())
        return self.send_external_message(signed_message)
    
    def send_many(self,
                  messages_with_modes: Iterable[MessageWithMode],
                  *,
                  allow_dangerous: bool = False) -> bytes:
        messages_with_modes = tuple(messages_with_modes)
        for _, mode in messages_with_modes:
            self._safety_check(mode, allow_dangerous)
        signed_message = self.create_signed_external(messages_with_modes, self.seqno())
        return self.send_external_message(signed_message)

    def seqno(self) -> int:
        s = self.run_get_method('seqno')
        match s:
            case int(): return s
            case _: raise TypeError(f'Unexpected result for seqno: {s!r}')

    @classmethod
    def from_private_key(cls,
                         private_key: bytes,
                         wc: int = 0,
                         provider: Provider | None = None) -> WalletV1R3:
        public_key = private_key_to_public_key(private_key)
        data = WalletV1R3Data.initial(public_key)
        address = cls.code_and_data_to_address(WALLET_V1R3_CODE, data.to_cell(), wc)
        return cls(address, private_key, provider)

    @classmethod
    def from_mnemonic(cls,
                      mnemonic: str,
                      wc: int = 0,
                      provider: Provider | None = None) -> WalletV1R3:
        private_key = mnemonic_to_private_key(mnemonic)
        return cls.from_private_key(private_key, wc, provider)

    @classmethod
    def create(cls,
               wc: int = 0,
               provider: Provider | None = None) -> tuple[WalletV1R3, str]:
        mnemonic = new_mnemonic()
        return cls.from_mnemonic(mnemonic, wc, provider), mnemonic
