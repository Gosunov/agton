from __future__ import annotations

from dataclasses import dataclass
from typing import Self, Callable

from ..cell import Slice, Builder
from .tlb import TlbConstructor
from .out_action import OutAction, out_action

@dataclass(frozen=True, slots=True)
class OutListEmpty(TlbConstructor):
    '''out_list_empty$_ = OutList 0;'''
    @classmethod
    def tag(cls) -> tuple[int, int] | None:
        return None

    @classmethod
    def deserialize_fields(cls, s: Slice) -> Self:
        return cls()

    def serialize_fields(self, b: Builder) -> Builder:
        return b

@dataclass(frozen=True, slots=True)
class OutListCons(TlbConstructor):
    '''out_list$_ {n:#} prev:^(OutList n) action:OutAction = OutList (n + 1);'''
    prev: OutList
    action: OutAction

    @classmethod
    def tag(cls) -> tuple[int, int] | None:
        return None

    @classmethod
    def deserialize_fields(cls, s: Slice) -> Self:
        prev = s.load_ref_tlb(out_list)
        action = s.load_tlb(out_action)
        return cls(prev, action)

    def serialize_fields(self, b: Builder) -> Builder:
        b.store_ref_tlb(self.prev)
        b.store_tlb(self.action)
        return b

OutList = OutListEmpty | OutListCons

def out_list(s: Slice) -> OutList:
    '''
    This is incorrect implementation,
    will work as long as after OutList there are no refs
    '''
    if s.remaining_refs > 0:
        return OutListCons.deserialize(s)
    return OutListEmpty.deserialize(s)
