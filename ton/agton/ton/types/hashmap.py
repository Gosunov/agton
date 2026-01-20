from __future__ import annotations

from typing import Callable, Self
from dataclasses import dataclass, field
from ..common import BitString, int2bs, bs2int

from ..cell import Slice
from ..cell import Builder, begin_cell
from ..cell import Cell, OrdinaryCell

from .msg_address import MsgAddress, Address, msg_address

from .tlb import TlbConstructor, TlbDeserializationError

'''
hm_edge#_ {n:#} {X:Type} {l:#} {m:#} label:(HmLabel ~l n) 
          {n = (~m) + l} node:(HashmapNode m X) = Hashmap n X;

hmn_leaf#_ {X:Type} value:X = HashmapNode 0 X;
hmn_fork#_ {n:#} {X:Type} left:^(Hashmap n X) 
           right:^(Hashmap n X) = HashmapNode (n + 1) X;

hml_short$0 {m:#} {n:#} len:(Unary ~n) {n <= m} s:(n * Bit) = HmLabel ~n m;
hml_long$10 {m:#} n:(#<= m) s:(n * Bit) = HmLabel ~n m;
hml_same$11 {m:#} v:Bit n:(#<= m) = HmLabel ~n m;

unary_zero$0 = Unary ~0;
unary_succ$1 {n:#} x:(Unary ~n) = Unary ~(n + 1);

hme_empty$0 {n:#} {X:Type} = HashmapE n X;
hme_root$1 {n:#} {X:Type} root:^(Hashmap n X) = HashmapE n X;
'''

@dataclass
class Hashmap:
    label: BitString
    node: Leaf | Fork

    def to_dict(self) -> dict[BitString, Slice]:
        d: dict[BitString, Slice] = dict()
        match self.node:
            case Leaf(s):
                d[self.label] = s.begin_parse()
                return d
            case Fork(l, r):
                left = l.to_dict()
                right = r.to_dict()
                for k, v in left.items():
                    label = BitString(self.label + BitString([0]) + k)
                    d[label] = v
                for k, v in right.items():
                    label = BitString(self.label + BitString([1]) + k)
                    d[label] = v
                return d

    @classmethod
    def from_dict(cls, d: dict[BitString, Slice]) -> Hashmap:
        def lcp(a: list[BitString]) -> int:
            # todo: Benchmark and maybe optimize, currently O(n * m)
            n = len(a)
            m = len(a[0])
            for i in range(m):
                b = a[0][i]
                for j in range(n):
                    if b != a[j][i]:
                        return i
            return n

        keys = list(d.keys())
        if len(keys) == 1:
            key = keys[0]
            return Hashmap(key, Leaf(d[key].to_cell()))
        k = lcp(keys)
        label = keys[0][:k]

        ld: dict[BitString, Slice] = dict()
        rd: dict[BitString, Slice] = dict()
        for key in keys:
            if key[k] == 0:
                ld[BitString(key[k + 1:])] = d[key]
            elif key[k] == 1:
                rd[BitString(key[k + 1:])] = d[key]
        l = cls.from_dict(ld)
        r = cls.from_dict(rd)

        return cls(BitString(label), Fork(l, r))

    def __eq__(self, value: object) -> bool:
        if not isinstance(value, Hashmap):
            return False
        return self.to_dict() == value.to_dict()

HashmapE = Hashmap | None

@dataclass
class Leaf:
    value: Cell

@dataclass
class Fork:
    left: Hashmap
    right: Hashmap

def load_unary(s: Slice) -> int:
    ans = 0
    while s.load_bit() == 1:
        ans += 1
    return ans

def store_unary(b: Builder, n: int) -> None:
    for _ in range(n):
        b.store_bit(1)
    b.store_bit(0)

def load_hml_short(s: Slice, m: int) -> tuple[BitString, int]:
    s.skip_prefix(int2bs(0b0, 1))
    n = load_unary(s)
    if not (n <= m):
        raise TlbDeserializationError()
    return s.load_bits(n), n

def load_hml_long(s: Slice, m: int) -> tuple[BitString, int]:
    s.skip_prefix(int2bs(0b10, 2))
    n = s.load_uint(m.bit_length())
    return s.load_bits(n), n

def load_hml_same(s: Slice, m: int) -> tuple[BitString, int]:
    s.skip_prefix(int2bs(0b11, 2))
    v = s.load_bit()
    n = s.load_uint(m.bit_length())
    return BitString([v] * n), n

def load_label(s: Slice, m: int) -> tuple[BitString, int]:
    tag = s.preload_uint(2)
    match tag:
        case 0b00 | 0b01: return load_hml_short(s, m)
        case 0b10: return load_hml_long(s, m)
        case 0b11: return load_hml_same(s, m)
    assert False

def store_hml_short(b: Builder, l: BitString, m: int) -> int:
    n = len(l)
    assert n <= m
    b.store_bit(0)
    store_unary(b, n)
    b.store_bits(l)
    return n

def hml_short_size(l: BitString, m: int) -> int:
    return 1 + len(l) + 1 + len(l)

def store_hml_long(b: Builder, l: BitString, m: int) -> int:
    n = len(l)
    b.store_uint(0b10, 2)
    b.store_uint(n, m.bit_length())
    b.store_bits(l)
    return n

def hml_long_size(l: BitString, m: int) -> int:
    return 2 + m.bit_length() + len(l)

def is_bits_same(l: BitString) -> tuple[bool, int]:
    if len(l) == 0:
        return False, -1
    for b in l:
        if b != l[0]:
            return False, -1
    return True, l[0]

def store_hml_same(b: Builder, l: BitString, m: int) -> int:
    n = len(l)
    same, bit = is_bits_same(l)
    assert same
    b.store_uint(0b11, 2)
    b.store_bit(bit)
    b.store_uint(n, m.bit_length())
    return n

def hml_same_size(l: BitString, m: int) -> int:
    same, _ = is_bits_same(l)
    if not same:
        return 1024
    return 2 + 1 + len(l)

def store_label(b: Builder, l: BitString, m: int) -> int:
    short_sz = hml_short_size(l, m)
    long_sz = hml_long_size(l, m)
    same_sz = hml_same_size(l, m)
    best_sz = min(short_sz, long_sz, same_sz)
    if best_sz == short_sz:
        return store_hml_short(b, l, m)
    if best_sz == long_sz:
        return store_hml_long(b, l, m)
    if best_sz == same_sz:
        return store_hml_same(b, l, m)
    assert False

def load_node(s: Slice, n: int) -> Leaf | Fork:
    if n == 0:
        return Leaf(s.to_cell())
    left = load_hashmap(s.load_ref().begin_parse(), n - 1)
    right = load_hashmap(s.load_ref().begin_parse(), n - 1)
    return Fork(left, right)

def store_node(b: Builder, node: Leaf | Fork, n: int) -> None:
    match node:
        case Leaf(v):
            b.store_slice(v.to_slice())
        case Fork(l, r):
            b.store_ref(store_hashmap(begin_cell(), l, n - 1).end_cell())
            b.store_ref(store_hashmap(begin_cell(), r, n - 1).end_cell())

def load_hashmap(s: Slice, n: int) -> Hashmap:
    label, l = load_label(s, n)
    m = n - l
    node = load_node(s, m)
    return Hashmap(label, node)

def store_hashmap(b: Builder, h: Hashmap, n: int) -> Builder:
    l = store_label(b, h.label, n)
    m = n - l
    store_node(b, h.node, m)
    return b

@dataclass(frozen=True, slots=True)
class HashmapCodec[K, V]:
    k_de: Callable[[BitString], K] | None = None
    k_se: Callable[[K], BitString] | None = None
    v_de: Callable[[Slice], V] | None = None
    v_se: Callable[[V], Slice] | None = None
    value_in_ref: bool = False

    def decode(self, hashmap: HashmapE) -> dict[K, V]:
        if self.k_de is None:
            raise ValueError('Key deserializator is not set')
        if self.v_de is None:
            raise ValueError('Value deserializator is not set')
        def v_de(s: Slice, f: Callable[[Slice], V]) -> V:
            if self.value_in_ref:
                s = s.load_ref().begin_parse()
            return f(s)

        d = {} if hashmap is None else hashmap.to_dict()
        return {self.k_de(k): v_de(v, self.v_de) for k, v in d.items()}
    
    def encode(self, d: dict[K, V]) -> HashmapE:
        if not d:
            return None
        if self.k_se is None or self.v_se is None:
            raise ValueError('Serializators are not set')
        def v_se(v: V, f: Callable[[V], Slice]) -> Slice:
            s = f(v)
            if not self.value_in_ref:
                return s
            s = begin_cell().store_ref(s.to_cell()).to_slice()
            return s

        cd = {self.k_se(k): v_se(v, self.v_se) for k, v in d.items()}
        hashmap = Hashmap.from_dict(cd)
        return hashmap
    
    def with_bool_values(self) -> HashmapCodec[K, bool]:
        def v_se(v: bool) -> Slice:
            return begin_cell().store_bool(v).to_slice()
        def v_de(s: Slice) -> bool:
            return s.load_bool()
        return HashmapCodec(self.k_de, self.k_se, v_de, v_se, self.value_in_ref)
    
    def with_int_values(self, n: int) -> HashmapCodec[K, int]:
        def v_se(v: int) -> Slice:
            return begin_cell().store_int(v, n).to_slice()
        def v_de(s: Slice) -> int:
            return s.load_int(n)
        return HashmapCodec(self.k_de, self.k_se, v_de, v_se, self.value_in_ref)
    
    def with_uint_values(self, n: int) -> HashmapCodec[K, int]:
        def v_se(v: int) -> Slice:
            return begin_cell().store_uint(v, n).to_slice()
        def v_de(s: Slice) -> int:
            return s.load_uint(n)
        return HashmapCodec(self.k_de, self.k_se, v_de, v_se, self.value_in_ref)
    
    def with_var_uint_values(self, n: int) -> HashmapCodec[K, int]:
        def v_se(v: int) -> Slice:
            return begin_cell().store_var_uint(v, n).to_slice()
        def v_de(s: Slice) -> int:
            return s.load_var_uint(n)
        return HashmapCodec(self.k_de, self.k_se, v_de, v_se, self.value_in_ref)
    
    def with_coins_values(self) -> HashmapCodec[K, int]:
        def v_se(v: int) -> Slice:
            return begin_cell().store_coins(v).to_slice()
        def v_de(s: Slice) -> int:
            return s.load_coins()
        return HashmapCodec(self.k_de, self.k_se, v_de, v_se, self.value_in_ref)
    
    def with_snake_string_values(self) -> HashmapCodec[K, str]:
        def v_se(v: str) -> Slice:
            return begin_cell().store_snake_string(v).to_slice()
        def v_de(s: Slice) -> str:
            return s.load_snake_string()
        return HashmapCodec(self.k_de, self.k_se, v_de, v_se, self.value_in_ref)
    
    def with_snake_bytes_values(self) -> HashmapCodec[K, bytes]:
        def v_se(v: bytes) -> Slice:
            return begin_cell().store_snake_bytes(v).to_slice()
        def v_de(s: Slice) -> bytes:
            return s.load_snake_bytes()
        return HashmapCodec(self.k_de, self.k_se, v_de, v_se, self.value_in_ref)
    
    def with_tlb_values[T: TlbConstructor](self, deserializer: type[T] | Callable[[Slice], T]) -> HashmapCodec[K, T]:
        def v_se(v: T) -> Slice:
            return begin_cell().store_tlb(v).to_slice()
        def v_de(s: Slice) -> T:
            return s.load_tlb(deserializer)
        return HashmapCodec(self.k_de, self.k_se, v_de, v_se, self.value_in_ref)
    
    def with_msg_address_values(self) -> HashmapCodec[K, MsgAddress]:
        def v_se(v: MsgAddress) -> Slice:
            return begin_cell().store_tlb(v).to_slice()
        def v_de(s: Slice) -> MsgAddress:
            return s.load_msg_address()
        return HashmapCodec(self.k_de, self.k_se, v_de, v_se, self.value_in_ref)
    
    def with_address_values(self) -> HashmapCodec[K, Address]:
        def v_se(v: Address) -> Slice:
            return begin_cell().store_tlb(v).to_slice()
        def v_de(s: Slice) -> Address:
            return s.load_tlb(Address)
        return HashmapCodec(self.k_de, self.k_se, v_de, v_se, self.value_in_ref)
    
    def with_int_keys(self, n: int) -> HashmapCodec[int, V]:
        def k_se(v: int) -> BitString:
            return begin_cell().store_int(v, n).to_cell().data
        def k_de(b: BitString) -> int:
            return bs2int(b, signed=True)
        return HashmapCodec(k_de, k_se, self.v_de, self.v_se, self.value_in_ref)
    
    def with_uint_keys(self, n: int) -> HashmapCodec[int, V]:
        def k_se(v: int) -> BitString:
            return begin_cell().store_uint(v, n).to_cell().data
        def k_de(b: BitString) -> int:
            return bs2int(b, signed=False)
        return HashmapCodec(k_de, k_se, self.v_de, self.v_se, self.value_in_ref)
    
    def with_bytes_keys(self, n: int) -> HashmapCodec[bytes, V]:
        def k_se(b: bytes) -> BitString:
            if len(b) != n:
                raise ValueError(f'Bytes length is {len(b)}, but {n} expected')
            return begin_cell().store_bytes(b).to_cell().data
        def k_de(b: BitString) -> bytes:
            return b.tobytes()
        return HashmapCodec(k_de, k_se, self.v_de, self.v_se, self.value_in_ref)
    
    def with_address_keys(self) -> HashmapCodec[Address, V]:
        def k_se(a: Address) -> BitString:
            return begin_cell().store_address(a).to_cell().data
        def k_de(b: BitString) -> Address:
            return OrdinaryCell(b).begin_parse().load_address()
        return HashmapCodec(k_de, k_se, self.v_de, self.v_se, self.value_in_ref)

    def with_inline_values(self) -> HashmapCodec[K, V]:
        return HashmapCodec(self.k_de, self.k_se, self.v_de, self.v_se, value_in_ref=False)
    
    def with_values_in_ref(self) -> HashmapCodec[K, V]:
        return HashmapCodec(self.k_de, self.k_se, self.v_de, self.v_se, value_in_ref=True)
