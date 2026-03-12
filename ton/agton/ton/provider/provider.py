from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Iterable

from agton.ton import Cell, Network
from agton.ton.types.tvm_value import TvmValue
from agton.ton.crypto import crc16
from agton.ton import MsgAddressInt, Message


class ProviderError(Exception):
    pass


class Provider(ABC):
    def __init__(self, network: Network):
        self.network = network

    @abstractmethod
    def raw_run_get_method(
        self, 
        a: MsgAddressInt,
        method_id: int,
        stack: tuple[TvmValue, ...],
        method: str | None = None
    ) -> tuple[TvmValue, ...]: ...

    @abstractmethod
    def raw_send_external_message(self, message: bytes) -> None: ...

    def _normalize_message(self, message: Message | Cell | bytes) -> Message:
        if isinstance(message, (bytes, bytearray, memoryview)):
            try:
                message = Cell.from_boc(message)
            except Exception as e:
                raise ValueError("Message is incorrectly serialized") from e
        if isinstance(message, Cell):
            try:
                message = Message.from_cell(message)
            except Exception as e:
                raise ValueError("Message is incorrectly serialized") from e
        return message
    
    def _normalize_stack(self, stack: Iterable[TvmValue] | TvmValue | None = None) -> tuple[TvmValue, ...]:
        if stack is None:
            return ()
        if isinstance(stack, Iterable):
            return tuple(stack)
        return (stack,)
    
    def send_external_message(self, message: Message | Cell | bytes) -> bytes:
        message = self._normalize_message(message)
        h = message.get_normalized_hash()
        self.raw_send_external_message(message.to_cell().to_boc())
        return h

    def run_get_method(self,
                       a: MsgAddressInt,
                       method_id: int | str,
                       stack: Iterable[TvmValue] | TvmValue | None = None) -> tuple[TvmValue, ...] | TvmValue:
        method_name_fallback = None if isinstance(method_id, int) else method_id
        if isinstance(method_id, str):
            t = int.from_bytes(crc16(method_id.encode()), byteorder='big')
            method_id = (t & 0xffff) | 0x10000
        stack = self._normalize_stack(stack)
        s = self.raw_run_get_method(a, method_id, stack, method_name_fallback)

        if len(s) == 1:
            return s[0]
        return s
