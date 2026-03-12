import base64

from typing import Literal

from .base_api_client import BaseApiClient
from .provider import Provider

from agton.ton import Cell, Slice, MsgAddressInt, Network
from agton.ton.types.tvm_value import TvmValue

class ToncenterError(Exception):
    pass

def encode_tvm_value(v: TvmValue) -> dict[str, str]:
    if isinstance(v, int):
        return {
            'type': 'num',
            'value': hex(v) 
        }
    if isinstance(v, Cell):
        return {
            'type': 'cell',
            'value': base64.b64encode(v.to_boc()).decode()
        }
    if isinstance(v, Slice):
        return {
            'type': 'slice',
            'value': base64.b64encode(v.to_cell().to_boc()).decode()
        }
    raise ToncenterError('Stack supports only int, Cell and Slice types')

def decode_tvm_value(d: dict[str, str]) -> TvmValue:
    type_ = d.get('type')
    value = d.get('value')
    if type_ is None:
        raise ToncenterError('No type for tvm value')
    if value is None:
        raise ToncenterError('No value for tvm value')

    if type_ == 'num':
        return int(value, base=16)
    if type_ == 'cell':
        return Cell.from_boc(base64.b64decode(value))
    if type_ == 'slice':
        return Cell.from_boc(base64.b64decode(value)).to_slice()

    raise ToncenterError(f'Unexpected type for tvm value: {type_}')
    

class ToncenterClient(Provider, BaseApiClient):
    def __init__(self, *,
                 network: Literal['testnet', 'mainnet'] | Network = 'testnet',
                 api_key: str | None = None):
        if network == 'testnet':
            network = Network.testnet
        elif network == 'mainnet':
            network = Network.mainnet
        Provider.__init__(self, network)
        host: str
        if network == Network.mainnet:
            host = 'https://toncenter.com/api/v3/'
        elif network == Network.testnet:
            host = 'https://testnet.toncenter.com/api/v3/'
        else:
            raise ToncenterError(f"Network should be 'mainnet' or 'testnet', but got {net}")
        
        BaseApiClient.__init__(self, host, api_key=('X-Api-Key', api_key) if api_key else None)


    def raw_run_get_method(self,
                        a: MsgAddressInt,
                        method_id: int,
                        stack: tuple[TvmValue, ...],
                        method: str | None = None) -> tuple[TvmValue, ...]:
        if method is None:
            raise ToncenterError('method_id as integer is not supported by Toncenter')
        data = {
            'address': str(a),
            'method': method,
            'stack': [
                encode_tvm_value(v) for v in stack
            ]
        }
        r = self.post('/runGetMethod', json=data)
        s = r['stack']
        c = r['exit_code']
        if c != 0:
            raise ToncenterError(f'Non zero exit code during get method: {c}')
        return tuple(decode_tvm_value(v) for v in s)

    def raw_send_external_message(self, message: bytes) -> None:
        data = {
            'boc': base64.b64encode(message).decode()
        }
        self.post('/message', json=data)
