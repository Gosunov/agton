from dataclasses import dataclass

from agton.ton import Contract, MsgAddress, Address, Cell, Slice, MessageRelaxed, CurrencyCollection, to_nano
from agton.jetton.messages import JettonTransfer, JettonBurn

@dataclass(frozen=True, slots=True)
class JettonWalletData:
    balance: int
    owner: Address
    jetton: Address
    jetton_wallet_code: Cell

class JettonWallet(Contract):
    def get_wallet_data(self) -> JettonWalletData:
        s = self.run_get_method('get_wallet_data')
        match s:
            case (
                int() as balance,
                Slice() as owner,
                Slice() as jetton,
                Cell() as jetton_wallet_code
            ):
                return JettonWalletData(
                    balance,
                    owner.load_address(),
                    jetton.load_address(),
                    jetton_wallet_code
                )
            case (
                int() as balance,
                Cell() as owner,
                Cell() as jetton,
                Cell() as jetton_wallet_code
            ):
                return JettonWalletData(
                    balance,
                    owner.begin_parse().load_address(),
                    jetton.begin_parse().load_address(),
                    jetton_wallet_code
                )
            case _:
                raise TypeError(f"Unexpected result for get_wallet_data: {s!r}")
    
    def create_jetton_transfer(self, *,
                               value: int | CurrencyCollection,
                               query_id: int,
                               amount: int,
                               destination: MsgAddress,
                               response_destination: MsgAddress,
                               custom_payload: Cell | None = None,
                               forward_amount: int = 0,
                               forward_payload: Cell = Cell.empty()) -> MessageRelaxed:
        body = JettonTransfer(
            query_id, amount, destination, response_destination,
            custom_payload, forward_amount, forward_payload
        )
        return self.create_internal_message(
            value=value,
            body=body.to_cell(),
        )
    
    def create_jetton_burn(self, *,
                           query_id: int,
                           amount: int,
                           response_destination: MsgAddress,
                           value: int | CurrencyCollection = to_nano(0.5),
                           custom_payload: Cell | None = None) -> MessageRelaxed:
        body = JettonBurn(
            query_id, amount, response_destination, custom_payload
        )
        return self.create_internal_message(
            value=value,
            body=body.to_cell()
        )
