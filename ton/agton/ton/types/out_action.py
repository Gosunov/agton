from dataclasses import dataclass
from typing import Self

from ..cell import Slice, Builder, Cell
from .tlb import TlbConstructor, TlbDeserializationError
from .message_relaxed import MessageRelaxed
from .currency_collection import CurrencyCollection


@dataclass(frozen=True, slots=True)
class ActionSendMsg(TlbConstructor):
    '''
    action_send_msg#0ec3c86d mode:(## 8) 
        out_msg:^(MessageRelaxed Any) = OutAction;
    '''
    mode: int
    out_msg: MessageRelaxed

    @classmethod
    def tag(cls) -> tuple[int, int]:
        return 0x0ec3c86d, 32

    @classmethod
    def deserialize_fields(cls, s: Slice) -> Self:
        mode = s.load_uint(8)
        out_msg = s.load_ref_tlb(MessageRelaxed)
        return cls(mode, out_msg)

    def serialize_fields(self, b: Builder) -> Builder:
        b.store_uint(self.mode, 8)
        b.store_ref_tlb(self.out_msg)
        return b

@dataclass(frozen=True, slots=True)
class ActionSetCode(TlbConstructor):
    '''action_set_code#ad4de08e new_code:^Cell = OutAction;'''
    new_code: Cell

    @classmethod
    def tag(cls) -> tuple[int, int]:
        return 0xad4de08e, 32

    @classmethod
    def deserialize_fields(cls, s: Slice) -> Self:
        new_code = s.load_ref()
        return cls(new_code)

    def serialize_fields(self, b: Builder) -> Builder:
        return b.store_ref(self.new_code)

@dataclass(frozen=True, slots=True)
class ActionReserveCurrency(TlbConstructor):
    '''
    action_reserve_currency#36e6b809 mode:(## 8)
        currency:CurrencyCollection = OutAction;
    '''
    mode: int
    currency: CurrencyCollection

    @classmethod
    def tag(cls) -> tuple[int, int]:
        return 0x36e6b809, 32

    @classmethod
    def deserialize_fields(cls, s: Slice) -> Self:
        mode = s.load_uint(8)
        currency = s.load_tlb(CurrencyCollection)
        return cls(mode, currency)

    def serialize_fields(self, b: Builder) -> Builder:
        b.store_uint(self.mode, 8)
        b.store_tlb(self.currency)
        return b

@dataclass(frozen=True, slots=True)
class ActionChangeLibrary(TlbConstructor):
    '''
    libref_hash$0 lib_hash:bits256 = LibRef;
    libref_ref$1 library:^Cell = LibRef;
    action_change_library#26fa1dd4 mode:(## 7)
        libref:LibRef = OutAction;
    '''
    mode: int
    library: Cell | bytes

    @classmethod
    def tag(cls) -> tuple[int, int]:
        return 0x26fa1dd4, 32

    @classmethod
    def deserialize_fields(cls, s: Slice) -> Self:
        mode = s.load_uint(7)
        library: Cell | bytes
        if s.load_bool():
            library = s.load_ref()
        else:
            library = s.load_bytes(32)
        return cls(mode, library)

    def serialize_fields(self, b: Builder) -> Builder:
        b.store_uint(self.mode, 7)
        b.store_bool(isinstance(self.library, Cell))
        if isinstance(self.library, Cell):
            b.store_ref(self.library)
        else:
            b.store_bytes(self.library)
        return b

OutAction = ActionSendMsg | ActionSetCode | ActionReserveCurrency | ActionChangeLibrary

def out_action(s: Slice) -> OutAction:
    tag = s.preload_uint(32)
    if tag == ActionSendMsg.tag()[0]:
        return ActionSendMsg.deserialize(s)
    if tag == ActionSetCode.tag()[0]:
        return ActionSetCode.deserialize(s)
    if tag == ActionReserveCurrency.tag()[0]:
        return ActionReserveCurrency.deserialize(s)
    if tag == ActionChangeLibrary.tag()[0]:
        return ActionChangeLibrary.deserialize(s)
    raise TlbDeserializationError(f'Unexpected tag for OutAction: {tag:08x}')
