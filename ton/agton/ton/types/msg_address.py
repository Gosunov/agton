from __future__ import annotations

import base64

from typing import Self
from bitarray import bitarray
from dataclasses import dataclass

from agton.ton.common.bitstring import BitString

from ..cell.slice import Slice
from ..cell.builder import Builder
from .tlb import TlbConstructor, TlbDeserializationError

from ..crypto import crc16


@dataclass(frozen=True, slots=True)
class AddrNone(TlbConstructor):
    '''addr_none$00 = MsgAddressExt'''

    @classmethod
    def tag(cls) -> tuple[int, int]:
        return 0b00, 2

    def serialize_fields(self, b: Builder) -> Builder:
        return b

    @classmethod
    def deserialize_fields(cls, s: Slice) -> Self:
        return cls()


@dataclass(frozen=True, slots=True)
class AddrExtern(TlbConstructor):
    '''
    addr_extern$01 len:(## 9) external_address:(bits len) 
    = MsgAddressExt;
    '''
    len: int
    external_address: BitString

    @classmethod
    def tag(cls) -> tuple[int, int]:
        return 0b01, 2
    
    def serialize_fields(self, b: Builder) -> Builder:
        b.store_uint(self.len, 9)
        b.store_bits(self.external_address)
        return b

    @classmethod
    def deserialize_fields(cls, s: Slice) -> Self:
        len = s.load_uint(9)
        external_address = s.load_bits(len)
        return cls(len, external_address)

@dataclass(frozen=True, slots=True)
class Anycast(TlbConstructor):
    '''
    anycast_info$_ depth:(#<= 30) { depth >= 1 }
    rewrite_pfx:(bits depth) = Anycast;
    '''
    depth: int
    rewrite_pfx: bitarray

    @classmethod
    def tag(cls) -> None:
        return None

    def serialize_fields(self, b: Builder) -> Builder:
        b.store_uint(self.depth, 5)
        b.store_bits(self.rewrite_pfx)
        return b

    @classmethod
    def deserialize_fields(cls, s: Slice) -> Self:
        depth = s.load_uint(5)
        if not (1 <= depth <= 30):
            raise TlbDeserializationError()
        rewrite_pfx = s.load_bits(depth)
        return cls(depth, rewrite_pfx)

PAYLOAD_LEN = 36
FLAG_TESTNET = 0x80
FLAG_BOUNCEABLE = 0x11
FLAG_NON_BOUNCEABLE = 0x51

@dataclass(frozen=True, slots=True)
class AddressFlags:
    bounceable: bool
    testnet_only: bool

@dataclass(frozen=True, slots=True)
class AddrStd(TlbConstructor):
    '''
    addr_std$10 anycast:(Maybe Anycast) 
    workchain_id:int8 address:bits256 = MsgAddressInt;
    '''
    workchain: int
    address: bytes
    anycast: Anycast | None = None

    def __post_init__(self):
        if len(self.address) != 32:
            raise ValueError("address hashpart must be exactly 32 bytes")

    @classmethod
    def tag(cls) -> tuple[int, int]:
        return 0b10, 2

    def serialize_fields(self, b: Builder) -> Builder:
        b.store_maybe_tlb(self.anycast)
        b.store_int(self.workchain, 8)
        b.store_bytes(self.address)
        return b

    @classmethod
    def deserialize_fields(cls, s: Slice) -> Self:
        anycast = s.load_maybe_tlb(Anycast)
        workchain = s.load_int(8)
        address = s.load_bytes(32)
        return cls(workchain, address, anycast)
    
    class ParseError(ValueError):
        pass

    @classmethod
    def parse_with_flags(cls, s: str) -> tuple[Self, AddressFlags]:
        if not isinstance(s, str) or not s:
            raise cls.ParseError("Address string is empty or not a string.")

        s = s.replace("-", "+").replace("_", "/")
        if len(s) % 4:
            s += "=" * (4 - (len(s) % 4))

        try:
            b = base64.b64decode(s, validate=True)
        except Exception as e:
            raise cls.ParseError(f"Invalid base64 string: {e}") from e

        if len(b) != PAYLOAD_LEN:
            raise cls.ParseError(
                f"Human readable form must be {PAYLOAD_LEN} bytes, got {len(b)}."
            )

        flags = b[0]
        wc = int.from_bytes(b[1:2], signed=True)
        addr = b[2:34]
        checksum = b[34:36]

        testnet_only = bool(flags & FLAG_TESTNET)
        flags &= ~FLAG_TESTNET

        if flags == FLAG_BOUNCEABLE:
            bounceable = True
        elif flags == FLAG_NON_BOUNCEABLE:
            bounceable = False
        else:
            raise cls.ParseError("Invalid address flags.")

        expected = crc16(b[:34])
        if expected != checksum:
            raise cls.ParseError("Invalid checksum.")

        return cls(wc, addr), AddressFlags(bounceable, testnet_only)

    @classmethod
    def parse(cls, s: str) -> Self:
        a, _ = cls.parse_with_flags(s)
        return a
    
    def raw(self) -> str:
        return f'{self.workchain}:{self.address.hex().zfill(32)}'
    
    def format(self, *,
               raw: bool = False,
               urlsafe: bool = True,
               bounceable: bool = True,
               testnet_only: bool = False) -> str:
        if raw:
            return self.raw()
        f = FLAG_BOUNCEABLE if bounceable else FLAG_NON_BOUNCEABLE
        if testnet_only:
            f |= FLAG_TESTNET

        buf = bytearray(PAYLOAD_LEN)
        buf[0] = f
        buf[1:2] = self.workchain.to_bytes(1, "big", signed=True)
        buf[2:34] = self.address
        buf[34:36] = crc16(buf[:34])

        b64_func = base64.urlsafe_b64encode if urlsafe else base64.b64encode
        encoded = b64_func(bytes(buf)).decode()

        return encoded
    
    def __format__(self, spec: str) -> str:
        raw = "r" in spec
        bounceable = "n" not in spec
        testnet_only = "t" in spec
        return self.format(
            raw=raw, urlsafe=True, bounceable=bounceable, testnet_only=testnet_only
        )

    def __repr__(self) -> str:
        return f'Address({self.format()})'
    
    def __str__(self) -> str:
        return self.format()


@dataclass(frozen=True, slots=True)
class AddrVar(TlbConstructor):
    '''
    addr_var$11 anycast:(Maybe Anycast) addr_len:(## 9) 
    workchain_id:int32 address:(bits addr_len) = MsgAddressInt;
    '''
    anycast: Anycast | None
    len: int
    workchain: int
    address: bitarray

    @classmethod
    def tag(cls) -> tuple[int, int]:
        return 0b11, 2

    def serialize_fields(self, b: Builder) -> Builder:
        b.store_maybe_tlb(self.anycast)
        b.store_int(self.len, 9)
        b.store_int(self.workchain, 32)
        b.store_bits(self.address)
        return b

    @classmethod
    def deserialize_fields(cls, s: Slice) -> Self:
        anycast = s.load_maybe_tlb(Anycast)
        len = s.load_uint(9)
        workchain = s.load_int(8)
        address = s.load_bits(len)
        return cls(anycast, len, workchain, address)

MsgAddressExt = AddrNone | AddrExtern
MsgAddressInt = AddrStd | AddrVar
MsgAddress = MsgAddressExt | MsgAddressInt

Address = AddrStd

def msg_address(s: Slice) -> MsgAddress:
    tag = s.preload_uint(2) 
    match tag:
        case 0b00: return AddrNone.deserialize(s)
        case 0b01: return AddrExtern.deserialize(s)
        case 0b10: return AddrStd.deserialize(s)
        case 0b11: return AddrVar.deserialize(s)
    assert False


def msg_address_ext(s: Slice) -> MsgAddressExt:
    tag = s.preload_uint(2) 
    match tag:
        case 0b00: return AddrNone.deserialize(s)
        case 0b01: return AddrExtern.deserialize(s)
    raise TlbDeserializationError()


def msg_address_int(s: Slice) -> MsgAddressInt:
    tag = s.preload_uint(2) 
    match tag:
        case 0b10: return AddrStd.deserialize(s)
        case 0b11: return AddrVar.deserialize(s)
    raise TlbDeserializationError()
