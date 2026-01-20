from __future__ import annotations

from typing import Self, Iterable

from ..cell.cell import Cell

from ..provider import Provider
from ..types import Address, StateInit, MessageRelaxed, Message, CurrencyCollection
from ..types import MsgAddressExt, AddrNone
from ..types.tvm_value import TvmValue

class ContractError(Exception):
    pass

class Contract:
    def __init__(self, address: Address, provider: Provider | None = None) -> None:
        self.address = address
        self.provider = provider
    
    def run_get_method(self,
                       method_id: int | str,
                       stack: Iterable[TvmValue] | TvmValue | None = None) -> tuple[TvmValue, ...] | TvmValue:
        if self.provider is None:
            raise ContractError('Cannot run get method without provider set')
        return self.provider.run_get_method(self.address, method_id, stack)
    
    def send_external_message(self, msg: Message) -> bytes:
        if self.provider is None:
            raise ContractError('Cannot send external message without provider set')
        return self.provider.send_external_message(msg)
    
    def create_internal_message(self, *,
                                value: int | CurrencyCollection = 0,
                                body: Cell = Cell.empty(),
                                bounce: bool = True,
                                init: StateInit | None = None) -> MessageRelaxed:
        return MessageRelaxed.internal(
            dest=self.address,
            value=value,
            body=body,
            bounce=bounce,
            init=init
        )
    
    def create_external_message(self,
                                body: Cell = Cell.empty(),
                                src: MsgAddressExt = AddrNone(),
                                init: StateInit | None = None) -> Message:
        return Message.external_in(
            src=src,
            dest=self.address,
            body=body,
            init=init
        )
    
    @staticmethod
    def state_init_to_address(state_init: StateInit, wc: int = 0) -> Address:
        return Address(wc, state_init.to_cell().hash())
    
    @staticmethod
    def code_and_data_to_address(code: Cell, data: Cell, wc: int = 0) -> Address:
        return Contract.state_init_to_address(StateInit(code=code, data=data), wc)
