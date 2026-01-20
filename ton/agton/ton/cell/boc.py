from typing import Sequence, Iterable

from bitarray import frozenbitarray, bitarray

from agton.ton import Cell
from agton.ton.cell import OrdinaryCell, PrunedBranchCell, LibraryRefCell, MerkleProofCell, MerkleUpdateCell
from agton.ton.crypto import crc32c
from agton.ton.common import BytesParser

BOC_MAGIC = b'\xb5\xee\x9c\x72'

def encode(roots: Sequence[Cell],
           with_crc: bool = False,
           with_index: bool = False,
           with_cache: bool = False,
           with_top_hash: bool = False,
           with_int_hashes: bool = False) -> bytes:
    if with_crc or with_index or with_cache or with_top_hash or with_int_hashes:
        raise NotImplementedError

    visited: set[Cell] = set()
    order: list[Cell] = []
    def dfs(c: Cell) -> None:
        if c in visited:
            return
        visited.add(c)
        for r in c.refs:
            dfs(r)
        order.append(c)
    for c in roots:
        dfs(c)

    order.reverse()
    index: dict[Cell, int] = dict()
    for i, c in enumerate(order):
        index[c] = i
    
    n = len(index)

    cell_size_bits = n.bit_length()
    cell_size_bytes = (cell_size_bits + 7) // 8

    payload = bytearray()
    for c in order:
        payload.extend(c._get_descriptors(c.level))
        payload.extend(c._get_data_bytes())
        for r in c.refs:
            payload.extend(index[r].to_bytes(cell_size_bytes, 'big'))
    size_bits = len(payload).bit_length()
    size_bytes = (size_bits + 7) // 8
    
    flags = 0
    flags |= cell_size_bytes

    boc = bytearray()
    boc.extend(BOC_MAGIC)
    boc.append(flags)
    boc.append(size_bytes)
    boc.extend(n.to_bytes(cell_size_bytes, 'big'))
    boc.extend(len(roots).to_bytes(cell_size_bytes, 'big'))
    boc.extend((0).to_bytes(cell_size_bytes, 'big'))
    boc.extend(len(payload).to_bytes(size_bytes, 'big'))
    for r in roots:
        boc.extend(index[r].to_bytes(cell_size_bytes, 'big'))
    boc.extend(payload)
    return bytes(boc)

class UnresolvedCell:
    def __init__(self, data: frozenbitarray, refs: Iterable[int], special: bool):
        self.data = data
        self.refs: tuple[int, ...] = tuple(refs)
        self.special = special
    
    def resolve(self, refs: Iterable[Cell]) -> Cell:
        refs = tuple(refs)
        if len(self.refs) != len(refs):
            raise ValueError(f'Invalid resolving, expected {len(self.refs)} refs, but {len(refs)} given')
        c = OrdinaryCell(self.data, refs)
        if self.special:
            tag = c.begin_parse().load_uint(8)
            match tag:
                case PrunedBranchCell.TAG: return PrunedBranchCell.from_ordinary_cell(c)
                case LibraryRefCell.TAG: return LibraryRefCell.from_ordinary_cell(c)
                case MerkleProofCell.TAG: return MerkleProofCell.from_ordinary_cell(c)
                case MerkleUpdateCell.TAG: return MerkleUpdateCell.from_ordinary_cell(c)
                case _: raise ValueError('Unknown tag for exotic cell: {tag:02x}')
        return c

def decode(boc: bytes) -> list[Cell]:
    parser = BytesParser(boc)
    parser.expect(BOC_MAGIC)
    flags = parser.load_uint(1)
    cell_size_bytes = flags & 7
    has_index = flags >> 7 & 1
    has_crc32c = flags >> 6 & 1
    has_cache_bits = flags >> 5 & 1

    if has_cache_bits and not has_index:
        raise ValueError("Cache flag can't be set without index flag")
    
    if has_crc32c:
        crc = crc32c(boc[:-4])
        expected = boc[-4:]
        if crc != expected:
            raise ValueError('Checksum does not match')
    size_bytes = parser.load_uint(1)
    cells_len = parser.load_uint(cell_size_bytes)
    roots_len = parser.load_uint(cell_size_bytes)
    absent = parser.load_uint(cell_size_bytes)
    if absent:
        raise NotImplementedError
    payload_size = parser.load_uint(size_bytes)
    roots_indexes: list[int] = []
    for i in range(roots_len):
        root_index = parser.load_uint(cell_size_bytes)
        roots_indexes.append(root_index)
    if has_index:
        for i in range(cells_len):
            l = parser.load_uint(size_bytes)
    payload = parser.load_bytes(payload_size)    
    if has_crc32c:
        parser.skip_bytes(4)
    parser.end_parse()

    unresolved_cells: list[UnresolvedCell] = []
    parser = BytesParser(payload)
    for i in range(cells_len):
        d1 = parser.load_uint(1)
        d2 = parser.load_uint(1)
        refs_len = d1 & 7
        special = d1 >> 3 & 1
        has_hashes = d1 >> 4 & 1
        level = d1 >> 5
        if refs_len > 4:
            raise ValueError(f'Too many refs in cell: {refs_len}')
        hashes_size = (level + 1) * 32 if has_hashes else 0
        depth_size = (level + 1) * 2 if has_hashes else 0
        if has_hashes:
            parser.skip_bytes(hashes_size + depth_size)

        is_padded = d2 & 1
        data_size = (d2 >> 1) + is_padded

        data_serialized = parser.load_bytes(data_size)
        data = bitarray()
        data.frombytes(data_serialized)

        if is_padded:
            i = len(data) - 1
            while i >= 0 and not data[i]:
                i -= 1
            data = data[:i]
        
        refs_indexes: list[int] = []
        for i in range(refs_len):
            refs_indexes.append(parser.load_uint(cell_size_bytes))
        unresolved_cells.append(UnresolvedCell(frozenbitarray(data), refs_indexes, bool(special)))
    parser.end_parse()

    cells: list[Cell | None] = [None] * cells_len
    for i, uc in reversed(list(enumerate(unresolved_cells))):
        refs: list[Cell] = []
        for r in uc.refs:
            t = cells[r]
            if t is None:
                raise ValueError('Topological order is broken')
            refs.append(t)
        cells[i] = uc.resolve(refs)
    
    roots: list[Cell] = []
    for i in roots_indexes:
        c = cells[i]
        if c is None:
            raise ValueError(f'Root with index {i} not found in BoC')
        roots.append(c)
    return roots
