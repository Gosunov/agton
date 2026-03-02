from __future__ import annotations

from dataclasses import dataclass

from agton.dedust.types import Asset, asset
from agton.ton import Slice, Builder, TlbConstructor

@dataclass(frozen=True, slots=True)
class CreateVolatilePool(TlbConstructor):
    '''
    create_volatile_pool#97d51f2f query_id:uint64 asset0:Asset asset1:Asset = InMsgBody;
    '''
    query_id: int
    asset0: Asset
    asset1: Asset

    @classmethod
    def tag(cls):
        return 0x97d51f2f, 32

    @classmethod
    def deserialize_fields(cls, s: Slice) -> CreateVolatilePool:
        query_id = s.load_uint(64)
        asset0 = s.load_tlb(asset.asset)
        asset1 = s.load_tlb(asset.asset)
        return cls(query_id, asset0, asset1)

    def serialize_fields(self, b: Builder) -> Builder:
        return (
            b
            .store_uint(self.query_id, 64)
            .store_tlb(self.asset0)
            .store_tlb(self.asset1)
        )
