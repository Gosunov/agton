import base64

from typing import Literal, Iterator, Iterable

from .base_api_client import BaseApiClient
from .provider import Provider

from agton.ton import Cell, Slice, MsgAddressInt, Address, Network, Account, Transaction
from agton.ton.types.account import account
from agton.ton.types.tvm_value import TvmValue

def encode_tvm_value(v: TvmValue) -> dict:
    if isinstance(v, int):
        return {
            'type': 'int257',
            'value': hex(v) 
        }
    if isinstance(v, Cell):
        return {
            'type': 'cell',
            'value': v.to_boc().hex()
        }
    if isinstance(v, Slice):
        return {
            'type': 'slice_boc_hex',
            'value': v.to_cell().to_boc().hex()
        }
    raise ValueError('Stack supports only int, Cell and Slice types')

def decode_tvm_value(d: dict) -> TvmValue:
    type_ = d.get('type')
    if type_ is None:
        raise ValueError('No type for tvm value')
    value = d.get(type_)
    if value is None:
        raise ValueError('No value for tvm value')

    if type_ == 'num':
        return int(value, base=16)
    if type_ == 'cell':
        return Cell.from_boc(value)
    if type_ == 'slice':
        return Cell.from_boc(value)
    if type_ == 'tuple':
        return tuple(decode_tvm_value(v) for v in value)

    raise ValueError(f'Unexpected type for tvm value: {type_}')

class TonApiClient(Provider, BaseApiClient):
    def __init__(self, *,
                 network: Literal['testnet', 'mainnet'] | Network = 'testnet',
                 api_key: str | None = None,
                 rps: float | None = None):
        if network == 'mainnet':
            network = Network.mainnet
        if network == 'testnet':
            network = Network.testnet
        Provider.__init__(self, network)

        host: str
        if network == Network.mainnet:
            host = 'https://tonapi.io/'
        elif network == Network.testnet:
            host = 'https://testnet.tonapi.io/'
        else:
            raise ValueError(f"Network should be 'mainnet' or 'testnet', but got {net}")

        BaseApiClient.__init__(self, host, bearer_token=api_key if api_key else None, rps=rps)


    def run_get_method(self, address: Address, method: str, args: Iterable[TvmValue] = ()) -> tuple[TvmValue, ...]:
        data = {
            'args': [
                encode_tvm_value(v) for v in args
            ]
        }
        url = f'/v2/blockchain/accounts/{address}/methods/{method}'
        r = self.post(url, json=data)
        s = r['stack']
        c = r['exit_code']
        if c != 0:
            raise ValueError(f'Non zero exit code during get method: {c}')
        return tuple(decode_tvm_value(v) for v in s)

    def raw_send_external_message(self, message: bytes) -> None:
        data = {
            'boc': message.hex()
        }
        self.post('/v2/blockchain/message', json=data)
    
    def get_account_state(self, address: Address) -> Account:
        url = f'/v2/liteserver/get_account_state/{address}'
        r = self.get(url)
        state = r['state']
        state = Cell.from_boc(state)
        return state.begin_parse().load_tlb(account)
    
    def get_account_transactions(self, address: Address) -> Iterator[Transaction]:
        url = f'/v2/blockchain/accounts/{address}/transactions'
        before_lt = None
        limit = 100
        while True:
            params = {"limit": limit}
            if before_lt is not None:
                params["before_lt"] = before_lt
            r = self.get(url, params=params)
            txs = r["transactions"]
            if not txs:
                break
            for tx in txs:
                raw = tx["raw"]
                cell = Cell.from_boc(raw)
                transaction = Transaction.from_cell(cell)
                yield transaction
            if len(txs) < limit:
                break 
            before_lt = txs[-1]["lt"]
