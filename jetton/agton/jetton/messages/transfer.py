from __future__ import annotations

from agton.ton import MsgAddress, Address, Cell, Builder, Slice, TlbConstructor
from dataclasses import dataclass

@dataclass(frozen=True, slots=True)
class JettonTransfer(TlbConstructor):
    '''
    transfer#0f8a7ea5 query_id:uint64 amount:(VarUInteger 16) destination:MsgAddress
                 response_destination:MsgAddress custom_payload:(Maybe ^Cell)
                 forward_ton_amount:(VarUInteger 16) forward_payload:(Either Cell ^Cell)
                 = InternalMsgBody;
    '''
    query_id: int
    amount: int
    destination: MsgAddress
    response_destination: MsgAddress
    custom_payload: Cell | None
    forward_amount: int
    forward_payload: Cell

    @classmethod
    def tag(cls):
        return 0x0f8a7ea5, 32

    def serialize_fields(self, b: Builder) -> Builder:
        b.store_uint(self.query_id, 64)
        b.store_coins(self.amount)
        b.store_msg_address(self.destination)
        b.store_msg_address(self.response_destination)
        b.store_maybe_ref(self.custom_payload)
        b.store_coins(self.forward_amount)
        b.store_maybe_ref(self.forward_payload)
        return b

    @classmethod
    def deserialize_fields(cls, s: Slice) -> JettonTransfer:
        query_id = s.load_uint(64)
        amount = s.load_coins()
        destination = s.load_msg_address()
        response_destination = s.load_msg_address()
        custom_payload = s.load_maybe_ref()
        forward_amount = s.load_coins()
        forward_payload_in_ref = s.load_bool()
        if forward_payload_in_ref:
            forward_payload = s.load_ref()
        else:
            forward_payload = s.load_cell()
        return cls(query_id, amount, destination, response_destination,
                   custom_payload, forward_amount, forward_payload)

@dataclass(frozen=True, slots=True)
class JettonInternalTransfer(TlbConstructor):
    '''
    Unspecified by TEP-74, but widely used

    internal_transfer#178d4519 query_id:uint64 amount:(VarUInteger 16) from:MsgAddress
                     response_address:MsgAddress
                     forward_ton_amount:(VarUInteger 16)
                     forward_payload:(Either Cell ^Cell)
                     = InternalMsgBody;
    '''
    query_id: int
    amount: int
    sender: MsgAddress
    response_destination: Address
    forward_amount: int
    forward_payload: Cell

    @classmethod
    def tag(cls) -> tuple[int, int] | None:
        return 0x178d4519, 32
    
    @classmethod
    def deserialize_fields(cls, s: Slice) -> JettonInternalTransfer:
        query_id = s.load_uint(64)
        amount = s.load_coins()
        sender = s.load_msg_address()
        response_destination = s.load_address()
        forward_amount = s.load_coins()
        forward_payload = s.load_maybe_ref()
        if forward_payload is None:
            forward_payload = Cell.empty()
        return cls(query_id, amount, sender, response_destination, forward_amount, forward_payload)

    def serialize_fields(self, b: Builder) -> Builder:
        b.store_uint(self.query_id, 64)
        b.store_coins(self.amount)
        b.store_msg_address(self.sender)
        b.store_address(self.response_destination)
        b.store_coins(self.forward_amount)
        b.store_maybe_ref(self.forward_payload)
        return b
