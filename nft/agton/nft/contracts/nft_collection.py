from dataclasses import dataclass
from typing import Iterator

from agton.ton import Contract, MsgAddress, Address, Cell, Slice
from .nft_item import NftItem

@dataclass(frozen=True, slots=True)
class NftCollectionData:
    next_item_index: int 
    collection_content: Cell 
    owner_address: MsgAddress

class NftCollection(Contract):
    def get_collection_data(self) -> NftCollectionData:
        s = self.run_get_method('get_collection_data')
        match s:
            case (
                int() as next_item_index,
                Cell() as collection_content,
                Cell() as owner_address
            ):
                return NftCollectionData(
                    next_item_index,
                    collection_content,
                    owner_address.begin_parse().load_msg_address(),
                )
            case _:
                raise TypeError(f"Unexpected result for get_collection_data: {s!r}")
    
    def get_nft_address(self, index: int) -> Address:
        s = self.run_get_method('get_nft_address_by_index', [index])
        match s:
            case (Slice() as cs,):
                return cs.load_address()
            case (Cell() as c,):
                return c.begin_parse().load_address()
            case _:
                raise TypeError(f"Unexpected result for get_nft_address_by_index: {s!r}")
    
    def get_nft(self, index: int) -> NftItem:
        nft_address = self.get_nft_address(index)
        return NftItem(nft_address, self.provider)

    def get_all_nfts(self) -> Iterator[NftItem]:
        n = self.get_collection_data().next_item_index
        if n == -1:
            raise ValueError('collection is not iterable, next_item_index is -1')
        for i in range(n):
            yield self.get_nft(i)
