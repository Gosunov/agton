from __future__ import annotations

from dataclasses import dataclass

from agton.dedust.types import Asset, asset
from agton.ton import Slice, Builder, TlbConstructor

@dataclass(frozen=True, slots=True)
class CreateVault(TlbConstructor):
    '''
    create_vault#21cfe02b query_id:uint64 asset:Asset = InMsgBody;
    '''
    query_id: int
    asset: Asset

    @classmethod
    def tag(cls):
        return 0x21cfe02b, 32

    @classmethod
    def deserialize_fields(cls, s: Slice) -> CreateVault:
        query_id = s.load_uint(64)
        asset_ = s.load_tlb(asset.asset)
        return cls(query_id, asset_)

    def serialize_fields(self, b: Builder) -> Builder:
        return (
            b
            .store_uint(self.query_id, 64)
            .store_tlb(self.asset)
        )
