from dataclasses import dataclass

from agton.ton import Contract, MsgAddress, Address, Cell, Slice, MessageRelaxed, CurrencyCollection, to_nano

@dataclass(frozen=True, slots=True)
class NftItemData:
    init: bool
    index: int
    collection_address: MsgAddress
    owner_address: MsgAddress
    individual_content: Cell

class NftItem(Contract):
    def get_nft_data(self) -> NftItemData:
        s = self.run_get_method('get_nft_data')
        match s:
            case (
                int() as init,
                int() as index,
                Cell() as collection_address,
                Cell() as owner_address,
                Cell() as individual_content
            ):
                return NftItemData(
                    bool(init),
                    index,
                    collection_address.begin_parse().load_msg_address(),
                    owner_address.begin_parse().load_msg_address(),
                    individual_content
                )
            case _:
                raise TypeError(f"Unexpected result for get_wallet_data: {s!r}")
