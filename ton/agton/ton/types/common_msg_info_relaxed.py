from __future__ import annotations

from dataclasses import dataclass
from typing import Self, Type

from ..cell.slice import Slice
from ..cell.builder import Builder

from .tlb import TlbConstructor, TlbDeserializationError

from .msg_address import MsgAddress, MsgAddressInt, MsgAddressExt
from .currency_collection import CurrencyCollection


@dataclass(frozen=True, slots=True)
class IntMsgInfoRelaxed(TlbConstructor):
    '''
    int_msg_info$0 ihr_disabled:Bool bounce:Bool bounced:Bool
        src:MsgAddress dest:MsgAddressInt 
        value:CurrencyCollection extra_flags:(VarUInteger 16) fwd_fee:Grams
        created_lt:uint64 created_at:uint32 = CommonMsgInfoRelaxed;
    '''
    ihr_disabled: bool
    bounce: bool
    bounced: bool
    src: MsgAddress
    dest: MsgAddressInt
    value: CurrencyCollection
    ihr_fee: int
    fwd_fee: int
    created_lt: int
    created_at: int

    @classmethod
    def tag(cls) -> tuple[int, int]:
        return 0b0, 1

    def serialize_fields(self, b: Builder) -> Builder:
        return (
            b
            .store_bool(self.ihr_disabled)
            .store_bool(self.bounce)
            .store_bool(self.bounced)
            .store_tlb(self.src)
            .store_tlb(self.dest)
            .store_tlb(self.value)
            .store_coins(self.ihr_fee)
            .store_coins(self.fwd_fee)
            .store_uint(self.created_lt, 64)
            .store_uint(self.created_at, 32)
        )

    @classmethod
    def deserialize_fields(cls, s: Slice) -> IntMsgInfoRelaxed:
        ihr_disabled = s.load_bool()
        bounce = s.load_bool()
        bounced = s.load_bool()
        src = s.load_msg_address()
        dest = s.load_msg_address_int()
        value = s.load_tlb(CurrencyCollection)
        ihr_fee = s.load_coins()
        fwd_fee = s.load_coins()
        created_lt = s.load_uint(64)
        created_at = s.load_uint(32)

        return cls(ihr_disabled, bounce, bounced, src, dest, value, ihr_fee, fwd_fee, created_lt, created_at)


@dataclass(frozen=True, slots=True)
class ExtOutInfoRelaxed(TlbConstructor):
    '''
    ext_out_msg_info$11 src:MsgAddress dest:MsgAddressExt
        created_lt:uint64 created_at:uint32 = CommonMsgInfoRelaxed;
    '''
    src: MsgAddress
    dest: MsgAddressExt
    created_lt: int
    created_at: int

    @classmethod
    def tag(cls) -> tuple[int, int]:
        return 0b11, 2

    def serialize_fields(self, b: Builder) -> Builder:
        return (
            b
            .store_tlb(self.src)
            .store_tlb(self.dest)
            .store_uint(self.created_lt, 64)
            .store_uint(self.created_at, 32)
        )

    @classmethod
    def deserialize_fields(cls, s: Slice) -> ExtOutInfoRelaxed:
        src = s.load_msg_address()
        dest = s.load_msg_address_ext()
        created_lt = s.load_uint(64)
        create_at = s.load_uint(32)
        return cls(src, dest, created_lt, create_at)

CommonMsgInfoRelaxed = IntMsgInfoRelaxed | ExtOutInfoRelaxed

def common_msg_relaxed(s: Slice) -> CommonMsgInfoRelaxed:
    tag = s.preload_uint(2)
    match tag:
        case 0b00 | 0b01: return IntMsgInfoRelaxed.deserialize(s)
        case 0b11: return ExtOutInfoRelaxed.deserialize(s)
    raise TlbDeserializationError
