from __future__ import annotations

from dataclasses import dataclass
from typing import Self, Type

from ..cell.slice import Slice
from ..cell.cell import Cell
from ..cell.builder import Builder

from .tlb import TlbConstructor

from .msg_address import MsgAddress, MsgAddressInt, MsgAddressExt, AddrNone
from .state_init import StateInit
from .common_msg_info_relaxed import CommonMsgInfoRelaxed, IntMsgInfoRelaxed, ExtOutInfoRelaxed
from .common_msg_info_relaxed import common_msg_relaxed
from .currency_collection import CurrencyCollection, ExtraCurrencyCollection

@dataclass(frozen=True, slots=True)
class MessageRelaxed(TlbConstructor):
    '''
    message$_ {X:Type} info:CommonMsgInfoRelaxed
        init:(Maybe (Either StateInit ^StateInit))
        body:(Either X ^X) = MessageRelaxed X;
    '''
    info: CommonMsgInfoRelaxed
    init: StateInit | None
    body: Cell

    @classmethod
    def tag(cls) -> None:
        return None

    @classmethod
    def deserialize_fields(cls, s: Slice) -> MessageRelaxed:
        info = s.load_tlb(common_msg_relaxed)
        init: StateInit | None
        has_init = s.load_bit()
        if has_init:
            init_in_ref = s.load_bit()
            if init_in_ref:
                init = StateInit.from_cell(s.load_ref())
            else:
                init = s.load_tlb(StateInit)
        else:
            init = None
        body: Cell = s.to_cell()
        body_in_ref = s.load_bit()
        if body_in_ref:
            body = s.load_ref()
        else:
            body = s.load_cell()
        return cls(info, init, body)

    def serialize_fields(self, b: Builder) -> Builder:
        if b is None:
            b = Builder()
        b.store_tlb(self.info)
        if self.init is None:
            b.store_bit(0)
        else:
            b.store_bit(1)
            init = self.init.to_cell()
            # can_inline_init = len(init.data) <= b.remaining_bits - 2
            # can_inline_init &= len(init.refs) <= b.remaining_refs - 1
            # can_inline_init &= not init.special
            can_inline_init = False
            if can_inline_init:
                b.store_bit(0)
                b.store_cell(init)
            else:
                b.store_bit(1)
                b.store_ref(init)

        body = self.body
        # can_inline_body = len(body.data) <= b.remaining_bits - 1
        # can_inline_body &= len(body.refs) <= b.remaining_refs
        # can_inline_body &= not body.special
        can_inline_body = body == Cell.empty()
        if can_inline_body:
            b.store_bit(0)
            b.store_cell(body)
        else:
            b.store_bit(1)
            b.store_ref(body)
        return b
    
    @classmethod
    def internal(cls, *,
                 value: int | CurrencyCollection,
                 dest: MsgAddressInt,
                 body: Cell = Cell.empty(),
                 src: MsgAddress = AddrNone(),
                 init: StateInit | None = None,
                 ihr_disabled: bool = True,
                 bounce: bool = True,
                 bounced: bool = False,
                 ihr_fee: int = 0,
                 fwd_fee: int = 0,
                 created_lt: int = 0,
                 created_at: int = 0) -> MessageRelaxed:
        if isinstance(value, int):
            value = CurrencyCollection(value, ExtraCurrencyCollection())
    
        info = IntMsgInfoRelaxed(
            ihr_disabled=ihr_disabled,
            bounce=bounce,
            bounced=bounced,
            src=src,
            dest=dest,
            value=value,
            ihr_fee=ihr_fee,
            fwd_fee=fwd_fee,
            created_lt=created_lt,
            created_at=created_at
        )
        return cls(info, init, body)

    @classmethod
    def external_out(cls, *,
                     body: Cell = Cell.empty(),
                     src: MsgAddress = AddrNone(),
                     dest: MsgAddressExt = AddrNone(),
                     init: StateInit | None = None,
                     created_lt: int = 0,
                     created_at: int = 0) -> MessageRelaxed:
        info = ExtOutInfoRelaxed(
            src=src,
            dest=dest,
            created_lt=created_lt,
            created_at=created_at
        )
        return cls(info, init, body)
