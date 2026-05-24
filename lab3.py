import argparse
import asyncio
from dataclasses import dataclass, field
import hashlib
import time
from types import CoroutineType
from typing import Any, Callable, Sequence
import typing

from ipv8.community import Community, CommunitySettings
from ipv8.configuration import ConfigBuilder, Strategy, WalkerDefinition, default_bootstrap_defs
from ipv8.keyvault.crypto import default_eccrypto
from ipv8.lazy_community import lazy_wrapper
from ipv8.messaging.payload import Payload
from ipv8.peer import Peer
from ipv8.peerdiscovery.network import PeerObserver
from ipv8_service import IPv8


LAB3_COMMUNITY_ID = bytes.fromhex("4c616233426c6f636b636861696e323032365057")
LAB3_OUR_COMMUNITY_ID = bytes.fromhex("776861743f3f3f3f3f3f3f3f3f3f3f3f3f3f3f3f")
LAB3_SERVER_PUBLIC_KEY_HEX = (
    "4c69624e61434c504b3ae3fc099fb56ca3b5e1de9a1c843387f2acdbb78b1bd4350ffde518068a0d246344b10d0d8c355fd0d76873e7d7f7838f3715e025af08f791324495e083331ce6"
)

with open("gid", "r") as f:
    GROUP_ID = f.read().strip()

TEAM_MEMBER_KEYS_HEX = [
    "4c69624e61434c504b3ae46676ba012e13d7e989930de441c5c74387a43d9b4c6d6f5037c783fa657c416a7791a2b1d45529e6804900465ec1608d64930f43f91b7c282fdec7b442d609",
    "4c69624e61434c504b3ab5d5fb13bc9a5a7c03efce411b71fa033e1f64aa9b2bacf672760c9991800c3c1e9088b94ce570f9c0e9dae8537014b84086b22ac1e5570b6d15e7f972574c29",
    "4c69624e61434c504b3a62250a7fcf0e526d3b228691b882a2bee18163907b3426d3e7c61e6c2474337212d86226da9d3e51dc82cf56491b0b171db113dd6f6a1147f938118a5dbae781",
]

DIFFICULTY = 22

class RegisterPayload(Payload):
    msg_id = 1
    format_list = ["varlenHutf8", "varlenH"]

    def __init__(self, group_id: str, community_id: bytes) -> None:
        self.group_id = group_id
        self.community_id = community_id

    def to_pack_list(self):
        return [
            ("varlenHutf8", self.group_id),
            ("varlenH", self.community_id),
        ]

    @classmethod
    def from_unpack_list(cls, group_id: str, community_id: bytes):
        return cls(group_id, community_id)


class RegistrationResponsePayload(Payload):
    msg_id = 2
    format_list = ["?", "varlenHutf8"]

    def __init__(self, success: bool, message: str) -> None:
        self.success = success
        self.message = message

    def to_pack_list(self):
        return [
            ("?", self.success),
            ("varlenHutf8", self.message),
        ]

    @classmethod
    def from_unpack_list(cls, success: bool, message: str):
        return cls(success, message)

def normalize_public_key_hex(key_hex: str) -> str:
    key_hex = key_hex.strip().lower()
    if key_hex.startswith("0x"):
        key_hex = key_hex[2:]
    bytes.fromhex(key_hex)
    return key_hex


def resolve_member_keys(raw_member_keys: Sequence[str]) -> list[str]:
    member_keys = [normalize_public_key_hex(key) for key in raw_member_keys]
    if len(member_keys) != 3:
        raise ValueError("Need exactly 3 member public keys.")
    if len(set(member_keys)) != 3:
        raise ValueError("Member public keys must be distinct.")
    return member_keys

class Lab3GlobalCommunity(Community, PeerObserver):
    community_id = LAB3_COMMUNITY_ID

    def __init__(self, settings: CommunitySettings) -> None:
        super().__init__(settings)

        self.add_message_handler(RegistrationResponsePayload, self.on_registration_response)

        self.done = asyncio.Event()
        self.registration_sent = False
        self.error: str | None = None

    def started(self) -> None:
        self.network.add_peer_observer(self)
        self.register_task("lab3_global_loop", self.loop, interval=0.3, delay=0.0)

    def configure(self, member_keys_hex: Sequence[str]) -> None:
        self.member_keys_hex = list(member_keys_hex)

    def on_peer_added(self, peer: Peer) -> None:
        key_hex = peer.public_key.key_to_bin().hex()
        if key_hex == LAB3_SERVER_PUBLIC_KEY_HEX:
            print("[Global] Found verified server.")
        elif key_hex in self.member_keys_hex:
            print(f"[Global] Found teammate: {key_hex}")

    def on_peer_removed(self, peer: Peer) -> None:
        pass

    def is_server(self, peer: Peer) -> bool:
        return peer.public_key.key_to_bin().hex() == LAB3_SERVER_PUBLIC_KEY_HEX

    def server_peer(self) -> Peer | None:
        for peer in self.get_peers():
            if self.is_server(peer):
                return peer
        return None

    async def loop(self) -> None:
        if self.done.is_set():
            return
        
        await self.try_register()

    async def try_register(self) -> None:
        if self.registration_sent:
            return

        server = self.server_peer()
        if server is None:
            return

        self.ez_send(server, RegisterPayload(GROUP_ID, LAB3_OUR_COMMUNITY_ID))
        self.registration_sent = True
        print("[Global] Sent registration.")

    @lazy_wrapper(RegistrationResponsePayload)
    def on_registration_response(self, peer: Peer, payload: RegistrationResponsePayload) -> None:
        if not self.is_server(peer):
            return

        print(payload.message)
        if not payload.success:
            self.error = payload.message
            self.done.set()
            return

        print(f"[Global] successfully registered community with server")
        self.done.set()


class BlockchainSubmitTransactionPayload(Payload):
    msg_id = 1
    format_list = ["varlenH", "varlenH", "q", "varlenH"]

    def __init__(self, sender_key: bytes, data: bytes, timestamp: int, signature: bytes) -> None:
        self.sender_key = sender_key
        self.data = data
        self.timestamp = timestamp
        self.signature = signature

    def to_pack_list(self):
        return [
            ("varlenH", self.sender_key),
            ("varlenH", self.data),
            ("q", self.timestamp),
            ("varlenH", self.signature),
        ]

    @classmethod
    def from_unpack_list(cls, sender_key: bytes, data: bytes, timestamp: int, signature: bytes):
        return cls(sender_key, data, timestamp, signature)
    
class BlockchainSubmitTransactionResponsePayload(Payload):
    msg_id = 2
    format_list = ["?", "varlenH", "varlenHutf8"]

    def __init__(self, success: bool, tx_hash: bytes, message: str) -> None:
        self.success = success
        self.tx_hash = tx_hash
        self.message = message

    def to_pack_list(self):
        return [
            ("?", self.success),
            ("varlenH", self.tx_hash),
            ("varlenHutf8", self.message),
        ]

    @classmethod
    def from_unpack_list(cls, success: bool, tx_hash: bytes, message: str):
        return cls(success, tx_hash, message)
    
class BlockchainGetChainHeightPayload(Payload):
    msg_id = 3
    format_list = ["q"]

    def __init__(self, request_id: int) -> None:
        self.request_id = request_id

    def to_pack_list(self):
        return [
            ("q", self.request_id),
        ]

    @classmethod
    def from_unpack_list(cls, request_id: int):
        return cls(request_id)

class BlockchainGetChainHeightResponsePayload(Payload):
    msg_id = 4
    format_list = ["q", "q", "varlenH"]

    def __init__(self, request_id: int, height: int, tip_hash: bytes) -> None:
        self.request_id = request_id
        self.height = height
        self.tip_hash = tip_hash

    def to_pack_list(self):
        return [
            ("q", self.request_id),
            ("q", self.height),
            ("varlenH", self.tip_hash),
        ]

    @classmethod
    def from_unpack_list(cls, request_id: int, height: int, tip_hash: bytes):
        return cls(request_id, height, tip_hash)

class BlockchainGetBlockPayload(Payload):
    msg_id = 5
    format_list = ["q"]

    def __init__(self, height: int) -> None:
        self.height = height

    def to_pack_list(self):
        return [
            ("q", self.height),
        ]

    @classmethod
    def from_unpack_list(cls, height: int):
        return cls(height)

class BlockchainGetBlockResponsePayload(Payload):
    msg_id = 6
    format_list = ["q", "varlenH", "varlenH", "q", "q", "q", "varlenH", "varlenH"]

    def __init__(self, height: int, prev_hash: bytes, txs_hash: bytes, timestamp: int, difficulty: int, nonce: int, block_hash: bytes, tx_hashes: bytes) -> None:
        self.height = height
        self.prev_hash = prev_hash
        self.txs_hash = txs_hash
        self.timestamp = timestamp
        self.difficulty = difficulty
        self.nonce = nonce
        self.block_hash = block_hash
        self.tx_hashes = tx_hashes

    def to_pack_list(self):
        return [
            ("q", self.height),
            ("varlenH", self.block_data),
            ("varlenH", self.prev_hash),
            ("q", self.timestamp),
            ("q", self.difficulty),
            ("q", self.nonce),
            ("varlenH", self.block_hash),
            ("varlenH", self.tx_hashes),
        ]

    @classmethod
    def from_unpack_list(cls, height: int, prev_hash: bytes, txs_hash: bytes, timestamp: int, difficulty: int, nonce: int, block_hash: bytes, tx_hashes: bytes):
        return cls(height, prev_hash, txs_hash, timestamp, difficulty, nonce, block_hash, tx_hashes)

def verify(sender_key: bytes, message: bytes, signature: bytes) -> bool:
    public_key = default_eccrypto.key_from_public_bin(sender_key)
    try:
        return public_key.verify(signature, message)
    except Exception:
        return False
    
class BlockHeader:
    def __init__(self, prev_hash: bytes, txs_hash: bytes, timestamp: int, difficulty: int, nonce: int = 0) -> None:
        self.prev_hash = prev_hash
        self.txs_hash = txs_hash
        self.timestamp = timestamp
        self.difficulty = difficulty
        self.nonce = nonce

    async def pow(self) -> None:
        while True:
            h = self.hash()
            whole_bytes = self.difficulty // 8
            if h[0:whole_bytes] == b"\x00" * whole_bytes and h[whole_bytes] < (1 << (8 - self.difficulty % 8)):
                break
            self.nonce += 1

            if self.nonce % 10000 == 0:
                await asyncio.sleep(0)

    def hash(self) -> bytes:
        return hashlib.sha256(
            self.prev_hash +
            self.txs_hash +
            self.timestamp.to_bytes(8, "big") +
            self.difficulty.to_bytes(4, "big") +
            self.nonce.to_bytes(8, "big")
        ).digest()

class Transaction:
    def __init__(self, sender_key: bytes, data: bytes, timestamp: int, signature: bytes) -> None:
        self.sender_key = sender_key
        self.data = data
        self.timestamp = timestamp
        self.signature = signature

        self.block_idx: int = -1
    
    def set_block_idx(self, block_idx: int) -> None:
        self.block_idx = block_idx

    def verify_signature(self) -> bool:
        return verify(self.sender_key, self.data, self.signature)

    def tx_hash(self) -> bytes:
        return hashlib.sha256(
            self.sender_key +
            self.data +
            self.timestamp.to_bytes(8, "big") +
            self.signature
        ).digest()

class Block:
    def __init__(self, header: BlockHeader, transaction: Transaction | None, mempool_id: bytes, height: int) -> None:
        self.header = header
        self.transaction = transaction
        self.mempool_id = mempool_id
        self.height = height

    def hash(self) -> bytes:
        return self.header.hash()

class Chain:
    def __init__(self, blocks: list[Block]) -> None:
        # the chain starts from the last transaction in the block list and goes back to the genesis block
        # the order of blocks in the list is from newest to oldest, i.e. blocks[0] is the tip of the chain and blocks[-1] is the genesis block
        self.blocks = blocks
    
    def validate(self) -> bool:
        for i in range(0, len(self.blocks)-1):
            if self.blocks[i].header.prev_hash != self.blocks[i+1].hash():
                return False
        return True
    
    def height(self) -> int:
        return len(self.blocks) - 1 # exclude genesis block
    
    def tip_block(self) -> Block:
        return self.blocks[0]
    
    def tx_hashes_in_chrono_order(self) -> list[bytes]:
        tx_hashes = []
        for block in reversed(self.blocks):
            if block.transaction is not None:
                tx_hashes.append(block.transaction.tx_hash())
        return tx_hashes
    
    def txs_hash(self) -> bytes:
        return hashlib.sha256(
            b''.join(self.tx_hashes_in_chrono_order())
        ).digest()


GENESIS_HEADER = BlockHeader(
    prev_hash=b"\x00" * 32,
    txs_hash=hashlib.sha256(b"").digest(),
    timestamp=0,
    difficulty=DIFFICULTY,
    nonce=6626595,
)

GENESIS = Block(GENESIS_HEADER, None, GENESIS_HEADER.hash(), 0)

TEST_MODE = False

async def await_if_necessary(value: Any) -> Any:
    if isinstance(value, CoroutineType):
        return await value
    return value

class Lab3BlockchainCommunity(Community):
    community_id = LAB3_OUR_COMMUNITY_ID

    def __init__(self, settings: CommunitySettings) -> None:
        super().__init__(settings)

        self.member_keys_hex: list[str] = []
        self.blocks: dict[bytes, Block] = {}
        self.blocks[GENESIS.hash()] = GENESIS
        self.tip_block: bytes = GENESIS.hash()
        self.done: asyncio.Event = asyncio.Event()
        self.error: str | None = None
        self.mempool: list[(Transaction, Callable[[BlockchainSubmitTransactionResponsePayload], Any])] = []

        self.add_message_handler(BlockchainSubmitTransactionPayload, self.on_submit_transaction)
        self.add_message_handler(BlockchainSubmitTransactionResponsePayload, self.on_submit_transaction_response)
        self.add_message_handler(BlockchainGetChainHeightPayload, self.on_get_chain_height)
        self.add_message_handler(BlockchainGetChainHeightResponsePayload, self.on_get_chain_height_response)
        self.add_message_handler(BlockchainGetBlockPayload, self.on_get_block)
        self.add_message_handler(BlockchainGetBlockResponsePayload, self.on_get_block_response)

    def _find_block_in_mempool_by_block_hash(self, h: bytes) -> Block | None:
        return self.blocks.get(h)

    def _compute_chain_from_block(self, block: Block) -> Chain:
        chain_blocks = []
        current_block = block
        while current_block != GENESIS:
            chain_blocks.append(current_block)
            prev_block = self._find_block_in_mempool_by_block_hash(current_block.header.prev_hash)
            if prev_block is None:
                raise ValueError("Invalid block: previous block not found in mempool.")
            current_block = prev_block
        chain_blocks.append(current_block)
        return Chain(chain_blocks)

    def on_peer_added(self, peer: Peer) -> None:
        key_hex = peer.public_key.key_to_bin().hex()
        if key_hex == LAB3_SERVER_PUBLIC_KEY_HEX:
            print("[Blockchain] Found verified server.")
        elif key_hex in self.member_keys_hex:
            print(f"[Blockchain] Found teammate: {key_hex}")

    def on_peer_removed(self, peer: Peer) -> None:
        pass

    def configure(self, member_keys_hex: Sequence[str]) -> None:
        self.member_keys_hex = list(member_keys_hex)

    def started(self) -> None:
        self.network.add_peer_observer(self)
        self.register_task("lab3_blockchain_loop", self.loop, interval=30, delay=0.0)
        self.register_task("lab3_mempool_loop", self.mempool_task, interval=5, delay=0.0)

    async def loop(self) -> None:
        if self.done.is_set():
            return
        
        print(f"[Test] Test mode is {TEST_MODE}")
        if TEST_MODE:
            await self.try_submit_transaction_test()

        return
    

    async def _on_test_continuation(self, response_payload: BlockchainSubmitTransactionResponsePayload) -> None:
        await self.on_submit_transaction_response_impl(self.my_peer, response_payload)

        await self.on_get_chain_height_impl(self.my_peer, BlockchainGetChainHeightPayload(request_id=0), self._on_test_continuation_2)

    async def _on_test_continuation_2(self, response_payload: BlockchainGetChainHeightResponsePayload) -> None:
        await self.on_get_chain_height_response_impl(self.my_peer, response_payload)

        await self.on_get_block_impl(self.my_peer, BlockchainGetBlockPayload(height=response_payload.height), self._on_test_continuation_3)

    async def _on_test_continuation_3(self, response_payload: BlockchainGetBlockResponsePayload) -> None:
        await self.on_get_block_response_impl(self.my_peer, response_payload)

        print("[Test] Test transaction flow completed.")

    async def try_submit_transaction_test(self) -> None:
        print("[Test] Submitting test transaction...")
        sender_key = self.my_peer.public_key.key_to_bin()
        data = f"Transaction {len(self.blocks)}".encode()
        timestamp = int(time.time())
        signature = self.my_peer.key.signature(data)

        await self.on_submit_transaction_impl(
            self.my_peer,
            BlockchainSubmitTransactionPayload(sender_key, data, timestamp, signature),
            self._on_test_continuation,
        )

    @lazy_wrapper(BlockchainSubmitTransactionPayload)
    async def on_submit_transaction(self, peer: Peer, payload: BlockchainSubmitTransactionPayload) -> None:
        await self.on_submit_transaction_impl(peer, payload, lambda response_payload: self.ez_send(peer, response_payload))

    async def mempool_task(self) -> None:
        try:
            transaction, resp = self.mempool.pop(0)
        except IndexError:
            return

        chain = self._compute_chain_from_block(self.blocks[self.tip_block])

        header = BlockHeader(
            prev_hash=self.tip_block,
            txs_hash=chain.txs_hash(),
            timestamp=transaction.timestamp,
            difficulty=DIFFICULTY,
        )
        print("[Blockchain] Mining block...")
        await header.pow()
        print(f"[Blockchain] Block mined with nonce {header.nonce} and hash {header.hash().hex()}")
        h = header.hash()
        self.blocks[h] = Block(header, transaction, h, chain.height() + 1)
        self.tip_block = h
        print(f"[Blockchain] Updated tip block to {self.tip_block.hex()} with hash {header.hash().hex()}")

        await await_if_necessary(resp(BlockchainSubmitTransactionResponsePayload(True, transaction.tx_hash(), "Transaction accepted.")))
                

    async def on_submit_transaction_impl(self,
                                         peer: Peer,
                                         payload: BlockchainSubmitTransactionPayload,
                                         resp: typing.Callable[[BlockchainSubmitTransactionResponsePayload], Any]
                                         ) -> None:
        print(f"[Blockchain] Received transaction submission from {peer} with data {payload.data.hex()} and timestamp {payload.timestamp}")

        transaction = Transaction(payload.sender_key, payload.data, payload.timestamp, payload.signature)

        print(f"[Blockchain] Transaction signature: {payload.signature.hex()}")
        print(f"[Blockchain] Transaction sender key: {payload.sender_key.hex()}")
        print(f"[Blockchain] Verifying transaction signature...")

        if not transaction.verify_signature():
            print("[Blockchain] Rejecting transaction with invalid signature.")

            await await_if_necessary(resp(BlockchainSubmitTransactionResponsePayload(False, transaction.tx_hash(), "Invalid signature.")))

            return

        print(f"[Blockchain] Transaction signature is valid. Accepting transaction.")

        self.mempool.append((transaction, resp))

        return
    
    @lazy_wrapper(BlockchainGetChainHeightPayload)
    async def on_get_chain_height(self, peer: Peer, payload: BlockchainGetChainHeightPayload) -> None:
        await self.on_get_chain_height_impl(peer, payload, lambda response_payload: self.ez_send(peer, response_payload))

    async def on_get_chain_height_impl(self, peer: Peer, payload: BlockchainGetChainHeightPayload, resp: typing.Callable[[BlockchainGetChainHeightResponsePayload], Any]) -> None:
        print(f"[Blockchain] Received chain height request from {peer} with request ID {payload.request_id}")

        print(f"[Blockchain] tip block is {self.tip_block.hex()}")
        chain = self._compute_chain_from_block(self.blocks[self.tip_block])

        await await_if_necessary(resp(BlockchainGetChainHeightResponsePayload(payload.request_id, chain.height(), chain.tip_block().hash())))

        return
    
    def _find_block_at_height(self, height: int) -> Block | None:
        if height < 0 or height >= len(self.blocks):
            return None
        tip = self.blocks.get(self.tip_block)
        if tip is None:
            return None
        chain = self._compute_chain_from_block(tip)
        if height > chain.height():
            return None
        for block in chain.blocks:
            print(f"[Blockchain] Checking block at height {block.height} with hash {block.hash().hex()}")
            if block.height == height:
                return block
        return None
    
    @lazy_wrapper(BlockchainGetBlockPayload)
    async def on_get_block(self, peer: Peer, payload: BlockchainGetBlockPayload) -> None:
        await self.on_get_block_impl(peer, payload, lambda response_payload: self.ez_send(peer, response_payload))

    async def on_get_block_impl(self, peer: Peer, payload: BlockchainGetBlockPayload, resp: typing.Callable[[BlockchainGetBlockResponsePayload], Any]) -> None:
        print(f"[Blockchain] Received block request from {peer} for height {payload.height}")

        block = self._find_block_at_height(payload.height)

        if block is None:
            print(f"[Blockchain] Invalid block height requested: {payload.height}")
            return
        
        chain = self._compute_chain_from_block(block)

        await await_if_necessary(resp(BlockchainGetBlockResponsePayload(
            height=payload.height,
            prev_hash=block.header.prev_hash,
            txs_hash=block.header.txs_hash,
            timestamp=block.header.timestamp,
            difficulty=block.header.difficulty,
            nonce=block.header.nonce,
            block_hash=block.hash(),
            tx_hashes=b"".join(chain.tx_hashes_in_chrono_order()),
        )))

        return

    @lazy_wrapper(BlockchainSubmitTransactionResponsePayload)
    async def on_submit_transaction_response(self, peer: Peer, payload: BlockchainSubmitTransactionResponsePayload) -> None:
        await self.on_submit_transaction_response_impl(peer, payload)
    
    async def on_submit_transaction_response_impl(self, peer: Peer, payload: BlockchainSubmitTransactionResponsePayload) -> None:
        print(f"[Blockchain] Received transaction submission response from {peer} with success {payload.success} and message {payload.message}")

        return
    
    @lazy_wrapper(BlockchainGetChainHeightResponsePayload)
    async def on_get_chain_height_response(self, peer: Peer, payload: BlockchainGetChainHeightResponsePayload) -> None:
        await self.on_get_chain_height_response_impl(peer, payload)
    
    async def on_get_chain_height_response_impl(self, peer: Peer, payload: BlockchainGetChainHeightResponsePayload) -> None:
        print(f"[Blockchain] Received chain height response from {peer} with request ID {payload.request_id}, height {payload.height} and tip hash {payload.tip_hash.hex()}")

        return
    
    @lazy_wrapper(BlockchainGetBlockResponsePayload)
    async def on_get_block_response(self, peer: Peer, payload: BlockchainGetBlockResponsePayload) -> None:
        await self.on_get_block_response_impl(peer, payload)
    
    async def on_get_block_response_impl(self, peer: Peer, payload: BlockchainGetBlockResponsePayload) -> None:
        print(f"[Blockchain] Received block response from {peer} for height {payload.height} with prev hash {payload.prev_hash.hex()} and txs hash {payload.txs_hash.hex()}")
        txs = '\n'.join([payload.tx_hashes[i:i+32].hex() for i in range(0, len(payload.tx_hashes), 32)])
        print(f"[Blockchain] TXS:\n{txs}")

        return

async def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--key", default="lab1_identity.pem")
    parser.add_argument("--port", type=int, default=8091)
    parser.add_argument("--register", action="store_true", default=False)
    parser.add_argument("--test-mode", action="store_true", default=False)
    parser.add_argument(
        "--member-key",
        action="append",
        dest="member_keys",
        help="Pass exactly 3 member public keys in canonical registration order.",
    )
    args = parser.parse_args()

    if args.test_mode:
        global TEST_MODE
        TEST_MODE = True

    raw_member_keys = args.member_keys if args.member_keys is not None else TEAM_MEMBER_KEYS_HEX
    member_keys_hex = resolve_member_keys(raw_member_keys)

    builder = ConfigBuilder().clear_keys().clear_overlays()
    builder.add_key("lab3key", "curve25519", args.key)
    builder.set_port(args.port)
    if args.register:
        builder.add_overlay(
            "Lab3GlobalCommunity",
            "lab3key",
            [WalkerDefinition(Strategy.RandomWalk,
                                                -1, {}),
            WalkerDefinition(Strategy.EdgeWalk,
                                                -1, {}),
            ],
            default_bootstrap_defs,
            {},
            [("started",)],
        )
    builder.add_overlay(
        "Lab3BlockchainCommunity",
        "lab3key",
        [WalkerDefinition(Strategy.RandomWalk,
                                            -1, {}),
        WalkerDefinition(Strategy.EdgeWalk,
                                            -1, {}),
        ],
        default_bootstrap_defs,
        {},
        [("started",)],
    )

    ipv8 = IPv8(builder.finalize(), extra_communities={"Lab3GlobalCommunity": Lab3GlobalCommunity, "Lab3BlockchainCommunity": Lab3BlockchainCommunity})
    await ipv8.start()

    overlays = [overlay for overlay in ipv8.overlays if isinstance(overlay, Lab3GlobalCommunity) or isinstance(overlay, Lab3BlockchainCommunity)]
    for overlay in overlays:
        overlay.configure(member_keys_hex)

    local_key_hex = overlays[0].my_peer.public_key.key_to_bin().hex()
    if local_key_hex not in member_keys_hex:
        await ipv8.stop()
        raise ValueError("Local key is not one of the 3 member keys.")

    print("IPv8 started for Lab 3.")
    print(f"My public key: {local_key_hex}")

    try:
        await overlays[0].done.wait()
        await overlays[1].done.wait()
    finally:
        await ipv8.stop()

    if overlays[0].error:
        raise RuntimeError(overlays[0].error)
    if overlays[1].error:
        raise RuntimeError(overlays[1].error)
    


if __name__ == "__main__":
    asyncio.run(main())

