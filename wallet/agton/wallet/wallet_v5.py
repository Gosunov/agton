from __future__ import annotations

from datetime import datetime, timedelta
from dataclasses import dataclass
from typing import Iterable

from itertools import repeat
from agton.ton import Cell, Builder, Slice, Provider, Address, MsgAddressInt, begin_cell
from agton.ton import Contract, HashmapCodec, Network, Message, MessageRelaxed, StateInit
from agton.ton.types import ActionSendMsg, CurrencyCollection
from agton.ton.types import OutList, OutListCons, OutListEmpty, out_list
from agton.ton.types.tlb import TlbConstructor, TlbDeserializationError
from agton.ton.crypto.signing import private_key_to_public_key

from agton.wallet.mnemonic import mnemonic_to_private_key, new_mnemonic

WALLET_V5_CODE = Cell.from_boc('b5ee9c7201021401000281000114ff00f4a413f4bcf2c80b01020120020302014804050102f20e02dcd020d749c120915b8f6320d70b1f2082106578746ebd21821073696e74bdb0925f03e082106578746eba8eb48020d72101d074d721fa4030fa44f828fa443058bd915be0ed44d0810141d721f4058307f40e6fa1319130e18040d721707fdb3ce03120d749810280b99130e070e2100f020120060702012008090019be5f0f6a2684080a0eb90fa02c02016e0a0b0201480c0d0019adce76a2684020eb90eb85ffc00019af1df6a2684010eb90eb858fc00017b325fb51341c75c875c2c7e00011b262fb513435c28020011e20d70b1f82107369676ebaf2e08a7f0f01e68ef0eda2edfb218308d722028308d723208020d721d31fd31fd31fed44d0d200d31f20d31fd3ffd70a000af90140ccf9109a28945f0adb31e1f2c087df02b35007b0f2d0845125baf2e0855036baf2e086f823bbf2d0882292f800de01a47fc8ca00cb1f01cf16c9ed542092f80fde70db3cd81003f6eda2edfb02f404216e926c218e4c0221d73930709421c700b38e2d01d72820761e436c20d749c008f2e09320d74ac002f2e09320d71d06c712c2005230b0f2d089d74cd7393001a4e86c128407bbf2e093d74ac000f2e093ed55e2d20001c000915be0ebd72c08142091709601d72c081c12e25210b1e30f20d74a111213009601fa4001fa44f828fa443058baf2e091ed44d0810141d718f405049d7fc8ca0040048307f453f2e08b8e14038307f45bf2e08c22d70a00216e01b3b0f2d090e2c85003cf1612f400c9ed54007230d72c08248e2d21f2e092d200ed44d0d2005113baf2d08f54503091319c01810140d721d70a00f2e08ee2c8ca0058cf16c9ed5493f2c08de20010935bdb31e1d74cd0')

@dataclass(frozen=True, slots=True)
class AddExtension(TlbConstructor):
    '''add_extension#02 addr:MsgAddressInt = W5ExtendedAction;'''
    addr: MsgAddressInt

    @classmethod
    def tag(cls):
        return 0x02, 8

    @classmethod
    def deserialize_fields(cls, s: Slice) -> AddExtension:
        addr = s.load_msg_address_int()
        return cls(addr)

    def serialize_fields(self, b: Builder) -> Builder:
        return b.store_msg_address_int(self.addr)


@dataclass(frozen=True, slots=True)
class DeleteExtension(TlbConstructor):
    '''delete_extension#03 addr:MsgAddressInt = W5ExtendedAction;'''
    addr: MsgAddressInt

    @classmethod
    def tag(cls):
        return 0x03, 8

    @classmethod
    def deserialize_fields(cls, s: Slice) -> DeleteExtension:
        addr = s.load_msg_address_int()
        return cls(addr)

    def serialize_fields(self, b: Builder) -> Builder:
        return b.store_msg_address_int(self.addr)


@dataclass(frozen=True, slots=True)
class SetSignatureAuthAllowed(TlbConstructor):
    '''set_signature_auth_allowed#04 allowed:Bool = W5ExtendedAction;'''
    allowed: bool

    @classmethod
    def tag(cls):
        return 0x04, 8

    @classmethod
    def deserialize_fields(cls, s: Slice) -> SetSignatureAuthAllowed:
        allowed = s.load_bool()
        return cls(allowed)

    def serialize_fields(self, b: Builder) -> Builder:
        return b.store_bool(self.allowed)

W5ExtendedAction = AddExtension | DeleteExtension | SetSignatureAuthAllowed

def w5_extended_action(s: Slice) -> W5ExtendedAction:
    tag = s.preload_uint(8)
    if tag == AddExtension.tag()[0]:
        return AddExtension.deserialize(s)
    if tag == DeleteExtension.tag()[0]:
        return DeleteExtension.deserialize(s)
    if tag == SetSignatureAuthAllowed.tag()[0]:
        return SetSignatureAuthAllowed.deserialize(s)
    raise TlbDeserializationError(f'Unknown tag for ExtendedAction: {tag:08x}')


@dataclass(frozen=True, slots=True)
class ExtendedListLast(TlbConstructor):
    '''extended_list_last$_ action:W5ExtendedAction = W5ExtendedActionList 0;'''
    action: W5ExtendedAction

    @classmethod
    def tag(cls):
        return None

    @classmethod
    def deserialize_fields(cls, s: Slice) -> ExtendedListLast:
        action = s.load_tlb(w5_extended_action)
        return cls(action)

    def serialize_fields(self, b: Builder) -> Builder:
        return b.store_tlb(self.action)

@dataclass(frozen=True, slots=True)
class ExtendedListCons(TlbConstructor):
    '''extended_list_action$_ {m:#} action:W5ExtendedAction prev:^(W5ExtendedActionList m) = W5ExtendedActionList (m + 1);'''
    action: W5ExtendedAction
    prev: W5ExtendedActionList

    @classmethod
    def tag(cls):
        return None

    @classmethod
    def deserialize_fields(cls, s: Slice) -> ExtendedListCons:
        action = s.load_tlb(w5_extended_action)
        prev = s.load_ref_tlb(w5_extended_action_list)
        return cls(action, prev)

    def serialize_fields(self, b: Builder) -> Builder:
        b.store_tlb(self.action)
        b.store_ref_tlb(self.prev)
        return b

W5ExtendedActionList = ExtendedListLast | ExtendedListCons

def w5_extended_action_list(s: Slice) -> W5ExtendedActionList:
    '''
    This is incorrect implementation
    will work as long as after W5ExtendedList in cell there are no possible refs
    '''
    if s.remaining_refs == 0:
        return ExtendedListLast.deserialize(s)
    return ExtendedListCons.deserialize(s)

@dataclass(frozen=True, slots=True)
class W5InnerRequest(TlbConstructor):
    '''
    w5_actions_request$_ {m:#} {n:#} 
        out_actions:(Maybe ^(OutList m)) 
        extended_actions:(Maybe (W5ExtendedActionList n)) 
        = W5InnerRequest m n;
    '''
    out_actions: OutList | None
    extended_actions: W5ExtendedActionList | None

    @classmethod
    def tag(cls):
        return None

    @classmethod
    def deserialize_fields(cls, s: Slice) -> W5InnerRequest:
        out_actions = s.load_maybe_ref_tlb(out_list)
        extended_actions = s.load_maybe_tlb(w5_extended_action_list)
        return cls(out_actions, extended_actions)

    def serialize_fields(self, b: Builder) -> Builder:
        b.store_maybe_ref_tlb(self.out_actions)
        b.store_maybe_tlb(self.extended_actions)
        return b

@dataclass(frozen=True, slots=True)
class W5SignedRequest(TlbConstructor):
    '''
    w5_signed_request$_ {m:#} {n:#}
        wallet_id:    uint32
        valid_until:  uint32
        msg_seqno:    uint32
        inner:        (W5InnerRequest m n)
        signature:    bits512
    = W5SignedRequest m n;
    '''
    wallet_id: int
    valid_until: int
    msg_seqno: int
    inner: W5InnerRequest
    signature: bytes

    @classmethod
    def tag(cls):
        return None

    @classmethod
    def deserialize_fields(cls, s: Slice) -> W5SignedRequest:
        wallet_id = s.load_uint(32)
        valid_until = s.load_uint(32)
        msg_seqno = s.load_uint(32)
        inner = s.load_tlb(W5InnerRequest)
        signature = s.load_bytes(64)
        return cls(wallet_id, valid_until, msg_seqno, inner, signature)

    def serialize_fields(self, b: Builder) -> Builder:
        b.store_uint(self.wallet_id, 32)
        b.store_uint(self.valid_until, 32)
        b.store_uint(self.msg_seqno, 32)
        b.store_tlb(self.inner)
        b.store_bytes(self.signature)
        return b
    
    @classmethod
    def create(cls,
               wallet_id: int,
               valid_until: int, 
               msg_seqno: int,
               inner: W5InnerRequest,
               private_key: bytes,
               for_external: bool) -> W5SignedRequest:
        prefix = W5ExternalSignedRequest.tag()[0] if for_external else W5InternalSignedRequest.tag()[0]
        b = (
            begin_cell()
            .store_uint(prefix, 32)
            .store_uint(wallet_id, 32)
            .store_uint(valid_until, 32)
            .store_uint(msg_seqno, 32)
            .store_tlb(inner)
        )
        signature = b.end_cell().sign(private_key)
        return cls(wallet_id, valid_until, msg_seqno, inner, signature)

    def __post_init__(self):
        if len(self.signature) != 64:
            raise ValueError(f'Expected 64 bytes in signature, but {len(self.signature)} found')

@dataclass(frozen=True, slots=True)
class W5InternalSignedRequest(TlbConstructor):
    '''w5_internal_signed_request#73696e74 {m:#} {n:#} request:(W5SignedRequest m n) = W5MsgBody m n;'''
    request: W5SignedRequest

    @classmethod
    def tag(cls):
        return 0x73696e74, 32

    @classmethod
    def deserialize_fields(cls, s: Slice) -> W5InternalSignedRequest:
        request = s.load_tlb(W5SignedRequest)
        return cls(request)

    def serialize_fields(self, b: Builder) -> Builder:
        return b.store_tlb(self.request)

@dataclass(frozen=True, slots=True)
class W5ExternalSignedRequest(TlbConstructor):
    '''w5_external_signed_request#7369676e {m:#} {n:#} request:(W5SignedRequest m n) = W5MsgBody m n;'''
    request: W5SignedRequest

    @classmethod
    def tag(cls):
        return 0x7369676e, 32

    @classmethod
    def deserialize_fields(cls, s: Slice) -> W5ExternalSignedRequest:
        request = s.load_tlb(W5SignedRequest)
        return cls(request)

    def serialize_fields(self, b: Builder) -> Builder:
        return b.store_tlb(self.request)

@dataclass(frozen=True, slots=True)
class W5ExtensionActionRequest(TlbConstructor):
    '''
    w5_extension_action_request#6578746e {m:#} {n:#}
        query_id:uint64 
        request:(W5InnerRequest m n) 
    = W5MsgBody m n;
    '''
    query_id: int
    request: W5InnerRequest

    @classmethod
    def tag(cls):
        return 0x6578746e, 32

    @classmethod
    def deserialize_fields(cls, s: Slice) -> W5ExtensionActionRequest:
        query_id = s.load_uint(64)
        request = s.load_tlb(W5InnerRequest)
        return cls(query_id, request)

    def serialize_fields(self, b: Builder) -> Builder:
        b.store_uint(self.query_id, 64)
        b.store_tlb(self.request)
        return b

W5MsgBody = W5InternalSignedRequest | W5ExternalSignedRequest | W5ExtensionActionRequest

def w5_msg_body(s: Slice) -> W5MsgBody:
    tag = s.preload_uint(64)
    if tag == W5InternalSignedRequest.tag()[0]:
        return W5InternalSignedRequest.deserialize(s)
    if tag == W5ExternalSignedRequest.tag()[0]:
        return W5ExternalSignedRequest.deserialize(s)
    if tag == W5ExtensionActionRequest.tag()[0]:
        return W5ExtensionActionRequest.deserialize(s)
    raise TlbDeserializationError(f'Unexpected tag for W5MsgBody: {tag:08x}')


@dataclass(frozen=True, slots=True)
class WalletV5Data(TlbConstructor):
    '''
    contract_state$_ 
        is_signature_allowed: bool
        seqno:                uint32
        wallet_id:            uint32
        public_key:           bits256
        extensions_dict:      (HashmapE 256 bool)
    = ContractState;
    '''
    is_signature_allowed: bool
    seqno: int
    wallet_id: int
    public_key: bytes
    extensions_dict: dict[bytes, bool]

    @classmethod
    def tag(cls):
        return None

    @classmethod
    def deserialize_fields(cls, s: Slice) -> WalletV5Data:
        is_signature_allowed = s.load_bool()
        seqno = s.load_uint(32)
        wallet_id = s.load_uint(32)
        public_key = s.load_bytes(32)
        extensions_codec = HashmapCodec().with_bytes_keys(32).with_bool_values()
        extensions_hashmap_e = s.load_hashmap_e(256)
        extensions_dict = extensions_codec.decode(extensions_hashmap_e)
        return cls(is_signature_allowed, seqno, wallet_id, public_key, extensions_dict)

    def serialize_fields(self, b: Builder) -> Builder:
        b.store_bool(self.is_signature_allowed)
        b.store_uint(self.seqno, 32)
        b.store_uint(self.wallet_id, 32)
        b.store_bytes(self.public_key)
        extensions_codec = HashmapCodec().with_bytes_keys(32).with_bool_values()
        extensions_hashmap_e = extensions_codec.encode(self.extensions_dict)
        b.store_hashmap_e(extensions_hashmap_e, 256)
        return b
    
    @staticmethod
    def calculate_wallet_id(net: Network,
                            wc: int,
                            wallet_version: int = 0,
                            counter: int = 0) -> int:
        context_id = -1 << 31
        context_id |= wc << (15 + 8)
        context_id |= wallet_version << 15
        context_id |= counter 
        return net.chain_id() ^ context_id

    @classmethod
    def initial(cls, public_key: bytes, wallet_id: int) -> WalletV5Data:
        return cls(
            is_signature_allowed=True,
            seqno=0,
            wallet_id=wallet_id,
            public_key=public_key,
            extensions_dict=dict()
        )

    def __post_init__(self):
        if len(self.public_key) != 32:
            raise ValueError(f'Expected 32 bytes in public_key, but {len(self.public_key)} found')

class WalletV5(Contract):
    def __init__(self,
                 provider: Provider,
                 address: Address,
                 private_key: bytes,
                 wallet_id: int) -> None:
        self.wallet_id = wallet_id
        self.private_key = private_key
        super().__init__(address, provider)
    
    def _create_request(self,
                        actions: Iterable[ActionSendMsg],
                        extended_actions: Iterable[W5ExtendedAction]) -> W5InnerRequest:
        actions = tuple(actions)
        extended_actions = tuple(extended_actions)[::-1]
        if len(actions) > 255:
            raise ValueError('WalletV5R1 supports only up to 255 messages')
        action_list = None
        if actions:
            action_list = OutListEmpty()
            for action in actions:
                action_list = OutListCons(action_list, action)
        extended_action_list = None
        if extended_actions:
            extended_action_list = ExtendedListLast(extended_actions[0])
            for extended_action in extended_actions[1:]:
                extended_action_list = ExtendedListCons(extended_action, extended_action_list)
        return W5InnerRequest(action_list, extended_action_list)

    def _create_signed_request(self, 
                               actions: Iterable[ActionSendMsg],
                               extended_actions: Iterable[W5ExtendedAction],
                               for_external: bool,
                               valid_until: int | None = None,
                               seqno: int | None = None,
                               use_dummy_private_key: bool = False) -> W5SignedRequest:
        if valid_until is None:
            t = datetime.now() + timedelta(minutes=3)
            valid_until = int(t.timestamp())
        if seqno is None:
            seqno = self.seqno()
        inner = self._create_request(actions, extended_actions)
        key = bytes([0] * 32) if use_dummy_private_key else self.private_key
        signed_request = W5SignedRequest.create(self.wallet_id, valid_until, seqno, inner, key, for_external)
        return signed_request

    def create_signed_external(self,
                               actions: Iterable[ActionSendMsg],
                               extended_actions: Iterable[W5ExtendedAction] = (),
                               seqno: int | None = None,
                               valid_until: int | None = None,
                               use_dummy_private_key: bool = False,
                               include_state_init: bool = False) -> Message:
        signed_request = self._create_signed_request(
            actions=actions, 
            extended_actions=extended_actions, 
            for_external=True, 
            valid_until=valid_until, 
            seqno=seqno, 
            use_dummy_private_key=use_dummy_private_key
        )
        external_signed_request = W5ExternalSignedRequest(signed_request)
        init = None
        if include_state_init:
            public_key = private_key_to_public_key(self.private_key)
            data = WalletV5Data.initial(public_key, self.wallet_id)
            init = StateInit(code=WALLET_V5_CODE, data=data.to_cell())
        return self.create_external_message(external_signed_request.to_cell(), init=init)
    
    def create_signed_internal_body(self,
                                    actions: Iterable[ActionSendMsg],
                                    extended_actions: Iterable[W5ExtendedAction] = (),
                                    seqno: int | None = None,
                                    valid_until: int | None = None,
                                    use_dummy_private_key: bool = False) -> W5InternalSignedRequest:
        signed_request = self._create_signed_request(
            actions=actions, 
            extended_actions=extended_actions, 
            for_external=False, 
            valid_until=valid_until, 
            seqno=seqno, 
            use_dummy_private_key=use_dummy_private_key
        )
        return W5InternalSignedRequest(signed_request)
    
    def create_signed_internal(self,
                               value: CurrencyCollection | int,
                               actions: Iterable[ActionSendMsg],
                               extended_actions: Iterable[W5ExtendedAction] = (),
                               seqno: int | None = None,
                               valid_until: int | None = None,
                               use_dummy_private_key: bool = False) -> MessageRelaxed:
        signed_request = self._create_signed_request(
            actions=actions, 
            extended_actions=extended_actions, 
            for_external=False, 
            valid_until=valid_until, 
            seqno=seqno, 
            use_dummy_private_key=use_dummy_private_key
        )
        return MessageRelaxed.internal(
            value=value,
            dest=self.address,
            body=W5InternalSignedRequest(signed_request).to_cell()
        )
    
    def create_extension_request(self,
                                 query_id: int,
                                 actions: Iterable[ActionSendMsg],
                                 extended_actions: Iterable[W5ExtendedAction] = ()) -> W5ExtensionActionRequest:
        request = self._create_request(actions, extended_actions)
        return W5ExtensionActionRequest(query_id, request)
    
    def create_extension_message(self,
                                 value: CurrencyCollection | int,
                                 query_id: int,
                                 actions: Iterable[ActionSendMsg],
                                 extended_actions: Iterable[W5ExtendedAction] = ()) -> MessageRelaxed:
        request = self._create_request(actions, extended_actions)
        return MessageRelaxed.internal(
            value=value,
            dest=self.address,
            body=W5ExtensionActionRequest(query_id, request).to_cell()
        )
    
    def _safety_check(self, mode: int, allow_dangerous: bool):
        if not (mode & 2) and not allow_dangerous:
            raise ValueError(
                'Sending message without SendIgnoreErrors flag set can be dangerous '
                'use alow_dangerous=True if you know what you doing, and want to suppress this error'
            )
    
    def execute(self,
                actions: Iterable[ActionSendMsg],
                extended_actions: Iterable[W5ExtendedAction] = (),
                seqno: int | None = None,
                valid_until: int | None = None,
                *,
                allow_dangerous: bool = False) -> bytes:
        for action in actions:
            self._safety_check(action.mode, allow_dangerous)
        signed_message = self.create_signed_external(actions, extended_actions, seqno, valid_until)
        return self.send_external_message(signed_message)
    
    def deploy_via_external(self) -> bytes:
        signed_message = self.create_signed_external(
            actions=(),
            valid_until=(1 << 32) - 1, 
            seqno=0,
            include_state_init=True
        )
        return self.send_external_message(signed_message)

    def send(self,
             msg: MessageRelaxed,
             mode: int = 3,
             valid_until: int | None = None,
             *,
             allow_dangerous: bool = False) -> bytes:
        return self.execute(
            actions=[ActionSendMsg(msg, mode)],
            extended_actions=[],
            seqno=None, 
            valid_until=valid_until,
            allow_dangerous=allow_dangerous
        )

    def seqno(self) -> int:
        s = self.run_get_method('seqno')
        match s:
            case int(): return s
            case _: raise TypeError(f'Unexpected result for seqno: {s!r}')
    
    def add_extension(self, address: Address, valid_until: int | None = None) -> bytes:
        return self.execute([], [AddExtension(address)], valid_until)
    
    def delete_extension(self, address: Address, valid_until: int | None = None) -> bytes:
        return self.execute([], [DeleteExtension(address)], valid_until)
    
    @classmethod
    def from_private_key(cls,
                         provider: Provider,
                         private_key: bytes,
                         counter: int = 0,
                         wc: int = 0) -> WalletV5:
        public_key = private_key_to_public_key(private_key)
        wallet_id = WalletV5Data.calculate_wallet_id(provider.network, wc, 0, counter)
        data = WalletV5Data.initial(public_key, wallet_id)
        address = Address.from_state_init(StateInit(
            code=WALLET_V5_CODE, 
            data=data.to_cell()
        ), wc)
        return cls(provider, address, private_key, wallet_id)

    @classmethod
    def from_mnemonic(cls,
                      provider: Provider,
                      mnemonic: str,
                      counter: int = 0,
                      wc: int = 0) -> WalletV5:
        private_key = mnemonic_to_private_key(mnemonic)
        return cls.from_private_key(provider, private_key, counter, wc)

    @classmethod
    def create(cls,
               provider: Provider,
               counter: int = 0,
               wc: int = 0) -> tuple[WalletV5, str]:
        mnemonic = new_mnemonic()
        return cls.from_mnemonic(provider, mnemonic, counter, wc), mnemonic
