import argparse
import asyncio
import hashlib
import itertools
import os
import random
import time
from dataclasses import dataclass
from types import CoroutineType
from typing import Any, Callable, Sequence

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

TEAM_MEMBER_KEYS_HEX = [
    "4c69624e61434c504b3ae46676ba012e13d7e989930de441c5c74387a43d9b4c6d6f5037c783fa657c416a7791a2b1d45529e6804900465ec1608d64930f43f91b7c282fdec7b442d609",
    "4c69624e61434c504b3ab5d5fb13bc9a5a7c03efce411b71fa033e1f64aa9b2bacf672760c9991800c3c1e9088b94ce570f9c0e9dae8537014b84086b22ac1e5570b6d15e7f972574c29",
    "4c69624e61434c504b3a62250a7fcf0e526d3b228691b882a2bee18163907b3426d3e7c61e6c2474337212d86226da9d3e51dc82cf56491b0b171db113dd6f6a1147f938118a5dbae781",
]

DIFFICULTY = 22
EMPTY_TXS_HASH = hashlib.sha256(b"").digest()
TEST_MODE = False


def load_group_id(cli_group_id: str | None) -> str:
    if cli_group_id is not None and cli_group_id.strip():
        return cli_group_id.strip()

    env_group_id = os.environ.get("LAB3_GROUP_ID", "").strip()
    if env_group_id:
        return env_group_id

    try:
        with open("gid", "r") as f:
            file_group_id = f.read().strip()
    except FileNotFoundError as exc:
        raise ValueError(
            "missing group id - pass --group-id <your lab 2 group id>, set LAB3_GROUP_ID, or create a ./gid file"
        ) from exc

    if not file_group_id:
        raise ValueError("./gid exists but is empty")

    return file_group_id


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
        raise ValueError("need exactly 3 member public keys")
    if len(set(member_keys)) != 3:
        raise ValueError("member public keys must be distinct")
    return member_keys


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def u64_be(value: int) -> bytes:
    return value.to_bytes(8, "big", signed=False)


def u32_be(value: int) -> bytes:
    return value.to_bytes(4, "big", signed=False)


def has_leading_zero_bits(digest: bytes, bits: int) -> bool:
    full_zero_bytes = bits // 8
    remaining_bits = bits % 8

    if digest[:full_zero_bytes] != b"\x00" * full_zero_bytes:
        return False
    if remaining_bits == 0:
        return True
    return digest[full_zero_bytes] < (1 << (8 - remaining_bits))


def compute_txs_hash(tx_hashes: Sequence[bytes]) -> bytes:
    return sha256(b"".join(tx_hashes))


class Lab3GlobalCommunity(Community, PeerObserver):
    community_id = LAB3_COMMUNITY_ID

    def __init__(self, settings: CommunitySettings) -> None:
        super().__init__(settings)

        self.add_message_handler(RegistrationResponsePayload, self.on_registration_response)

        self.done = asyncio.Event()
        self.registration_sent = False
        self.error: str | None = None
        self.group_id: str | None = None

    def started(self) -> None:
        self.network.add_peer_observer(self)
        self.register_task("lab3_global_loop", self.loop, interval=0.3, delay=0.0)

    def configure(self, member_keys_hex: Sequence[str], group_id: str) -> None:
        self.member_keys_hex = list(member_keys_hex)
        self.group_id = group_id

    def on_peer_added(self, peer: Peer) -> None:
        key_hex = peer.public_key.key_to_bin().hex()
        if key_hex == LAB3_SERVER_PUBLIC_KEY_HEX:
            print("[global] found verified server")
        elif key_hex in self.member_keys_hex:
            print(f"[global] found teammate {key_hex}")

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

        if self.group_id is None:
            raise ValueError("group id is not configured")

        self.ez_send(server, RegisterPayload(self.group_id, LAB3_OUR_COMMUNITY_ID))
        self.registration_sent = True
        print("[global] sent registration")

    @lazy_wrapper(RegistrationResponsePayload)
    def on_registration_response(self, peer: Peer, payload: RegistrationResponsePayload) -> None:
        if not self.is_server(peer):
            return

        print(payload.message)
        if not payload.success:
            self.error = payload.message
            self.done.set()
            return

        print("[global] registered community with server")
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
        return [("q", self.request_id)]

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
        return [("q", self.height)]

    @classmethod
    def from_unpack_list(cls, height: int):
        return cls(height)


class BlockchainGetBlockResponsePayload(Payload):
    msg_id = 6
    format_list = ["q", "varlenH", "varlenH", "q", "q", "q", "varlenH", "varlenH"]

    def __init__(
        self,
        height: int,
        prev_hash: bytes,
        txs_hash: bytes,
        timestamp: int,
        difficulty: int,
        nonce: int,
        block_hash: bytes,
        tx_hashes: bytes,
    ) -> None:
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
            ("varlenH", self.prev_hash),
            ("varlenH", self.txs_hash),
            ("q", self.timestamp),
            ("q", self.difficulty),
            ("q", self.nonce),
            ("varlenH", self.block_hash),
            ("varlenH", self.tx_hashes),
        ]

    @classmethod
    def from_unpack_list(
        cls,
        height: int,
        prev_hash: bytes,
        txs_hash: bytes,
        timestamp: int,
        difficulty: int,
        nonce: int,
        block_hash: bytes,
        tx_hashes: bytes,
    ):
        return cls(height, prev_hash, txs_hash, timestamp, difficulty, nonce, block_hash, tx_hashes)


class BlockchainAnnounceBlockPayload(Payload):
    msg_id = 7
    format_list = ["q", "varlenH", "varlenH", "q", "q", "q", "varlenH", "varlenH"]

    def __init__(
        self,
        height: int,
        prev_hash: bytes,
        txs_hash: bytes,
        timestamp: int,
        difficulty: int,
        nonce: int,
        block_hash: bytes,
        tx_hashes: bytes,
    ) -> None:
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
            ("varlenH", self.prev_hash),
            ("varlenH", self.txs_hash),
            ("q", self.timestamp),
            ("q", self.difficulty),
            ("q", self.nonce),
            ("varlenH", self.block_hash),
            ("varlenH", self.tx_hashes),
        ]

    @classmethod
    def from_unpack_list(
        cls,
        height: int,
        prev_hash: bytes,
        txs_hash: bytes,
        timestamp: int,
        difficulty: int,
        nonce: int,
        block_hash: bytes,
        tx_hashes: bytes,
    ):
        return cls(height, prev_hash, txs_hash, timestamp, difficulty, nonce, block_hash, tx_hashes)


def verify(sender_key: bytes, message: bytes, signature: bytes) -> bool:
    public_key = default_eccrypto.key_from_public_bin(sender_key)
    try:
        return public_key.verify(signature, message)
    except Exception:
        return False


@dataclass(frozen=True)
class Transaction:
    sender_key: bytes
    data: bytes
    timestamp: int
    signature: bytes

    def signed_message(self) -> bytes:
        return self.sender_key + self.data + u64_be(self.timestamp)

    def verify_signature(self) -> bool:
        return verify(self.sender_key, self.signed_message(), self.signature)

    def tx_hash(self) -> bytes:
        return sha256(self.sender_key + self.data + u64_be(self.timestamp) + self.signature)


@dataclass(frozen=True)
class BlockHeader:
    prev_hash: bytes
    txs_hash: bytes
    timestamp: int
    difficulty: int
    nonce: int = 0

    def pack(self) -> bytes:
        return self.prev_hash + self.txs_hash + u64_be(self.timestamp) + u32_be(self.difficulty) + u64_be(self.nonce)

    def hash(self) -> bytes:
        return sha256(self.pack())


@dataclass(frozen=True)
class Block:
    height: int
    header: BlockHeader
    tx_hashes: tuple[bytes, ...]

    def hash(self) -> bytes:
        return self.header.hash()


GENESIS = Block(
    height=0,
    header=BlockHeader(
        prev_hash=b"\x00" * 32,
        txs_hash=EMPTY_TXS_HASH,
        timestamp=0,
        difficulty=DIFFICULTY,
        nonce=6626595,
    ),
    tx_hashes=(),
)


async def await_if_necessary(value: Any) -> Any:
    if isinstance(value, CoroutineType):
        return await value
    return value


class Lab3BlockchainCommunity(Community, PeerObserver):
    community_id = LAB3_OUR_COMMUNITY_ID

    def __init__(self, settings: CommunitySettings) -> None:
        super().__init__(settings)

        self.member_keys_hex: list[str] = []
        self.blocks_by_hash: dict[bytes, Block] = {GENESIS.hash(): GENESIS}
        self.blocks_by_height: dict[int, bytes] = {0: GENESIS.hash()}
        self.tip_hash: bytes = GENESIS.hash()
        self.done = asyncio.Event()
        self.error: str | None = None
        self.mempool: dict[bytes, Transaction] = {}
        self.known_transactions: dict[bytes, Transaction] = {}  # Changed to dict to track actual transactions for reorgs
        self.pending_request_ids: itertools.count[int] = itertools.count(1)
        self.pending_height_requests: dict[int, asyncio.Future[BlockchainGetChainHeightResponsePayload]] = {}
        self.pending_block_requests: dict[int, asyncio.Future[BlockchainGetBlockResponsePayload]] = {}
        self.local_key_hex: str | None = None
        self.empty_blocks_after_transaction = 3
        self.blocks_since_last_nonempty = 0

        self.add_message_handler(BlockchainSubmitTransactionPayload, self.on_submit_transaction)
        self.add_message_handler(BlockchainSubmitTransactionResponsePayload, self.on_submit_transaction_response)
        self.add_message_handler(BlockchainGetChainHeightPayload, self.on_get_chain_height)
        self.add_message_handler(BlockchainGetChainHeightResponsePayload, self.on_get_chain_height_response)
        self.add_message_handler(BlockchainGetBlockPayload, self.on_get_block)
        self.add_message_handler(BlockchainGetBlockResponsePayload, self.on_get_block_response)
        self.add_message_handler(BlockchainAnnounceBlockPayload, self.on_announce_block)

    def configure(self, member_keys_hex: Sequence[str], miner_key_hex: str | None = None) -> None:
        self.member_keys_hex = list(member_keys_hex)
        self.local_key_hex = self.my_peer.public_key.key_to_bin().hex()

    def started(self) -> None:
        self.network.add_peer_observer(self)
        self.register_task("lab3_consensus_loop", self.consensus_loop, interval=1.0, delay=0.0)
        self.register_task("lab3_sync_loop", self.sync_loop, interval=2.0, delay=1.0)

    def on_peer_added(self, peer: Peer) -> None:
        key_hex = peer.public_key.key_to_bin().hex()
        if key_hex == LAB3_SERVER_PUBLIC_KEY_HEX:
            print("[blockchain] found verified server")
        elif key_hex in self.member_keys_hex:
            print(f"[blockchain] found teammate {key_hex} (peer miner)")

    def on_peer_removed(self, peer: Peer) -> None:
        pass

    def is_server(self, peer: Peer) -> bool:
        return peer.public_key.key_to_bin().hex() == LAB3_SERVER_PUBLIC_KEY_HEX

    def is_teammate(self, peer: Peer) -> bool:
        return peer.public_key.key_to_bin().hex() in self.member_keys_hex

    def peer_key_hex(self, peer: Peer) -> str:
        return peer.public_key.key_to_bin().hex()

    def current_height(self) -> int:
        return self.blocks_by_hash[self.tip_hash].height

    def current_tip(self) -> Block:
        return self.blocks_by_hash[self.tip_hash]

    def teammate_peers(self) -> list[Peer]:
        return [peer for peer in self.get_peers() if self.is_teammate(peer)]

    def _find_block_at_height(self, height: int) -> Block | None:
        block_hash = self.blocks_by_height.get(height)
        if block_hash is None:
            return None
        return self.blocks_by_hash.get(block_hash)

    def _build_block_payload(self, block: Block, payload_cls: type[Payload]) -> Payload:
        return payload_cls(
            height=block.height,
            prev_hash=block.header.prev_hash,
            txs_hash=block.header.txs_hash,
            timestamp=block.header.timestamp,
            difficulty=block.header.difficulty,
            nonce=block.header.nonce,
            block_hash=block.hash(),
            tx_hashes=b"".join(block.tx_hashes),
        )

    def _payload_to_block(self, payload: BlockchainGetBlockResponsePayload | BlockchainAnnounceBlockPayload) -> Block:
        tx_hashes_bytes = payload.tx_hashes
        if len(tx_hashes_bytes) % 32 != 0:
            raise ValueError("invalid tx_hashes payload length")
        tx_hashes = tuple(tx_hashes_bytes[i:i + 32] for i in range(0, len(tx_hashes_bytes), 32))
        header = BlockHeader(
            prev_hash=payload.prev_hash,
            txs_hash=payload.txs_hash,
            timestamp=payload.timestamp,
            difficulty=payload.difficulty,
            nonce=payload.nonce,
        )
        if header.hash() != payload.block_hash:
            raise ValueError("block hash does not match header")
        return Block(height=payload.height, header=header, tx_hashes=tx_hashes)

    def _validate_block(self, block: Block) -> None:
        if compute_txs_hash(block.tx_hashes) != block.header.txs_hash:
            raise ValueError("invalid transaction commitment")
        if not has_leading_zero_bits(block.hash(), block.header.difficulty):
            raise ValueError("invalid proof of work")
        if block.height == 0:
            if block.hash() != GENESIS.hash():
                raise ValueError("invalid genesis block")
            return

        prev_block = self.blocks_by_hash.get(block.header.prev_hash)
        if prev_block is None:
            raise ValueError("previous block missing")
        if prev_block.height + 1 != block.height:
            raise ValueError("height does not match parent")
        if block.header.timestamp < prev_block.header.timestamp:
            raise ValueError("timestamp moved backwards")

    def _adopt_block(self, block: Block) -> bool:
        known = self.blocks_by_hash.get(block.hash())
        if known is not None:
            # Tie breaker/longest chain resolution logic if we find a longer path via known forks
            if block.height > self.current_height():
                self.tip_hash = block.hash()
                self._rebuild_canonical_index()
            return False

        self._validate_block(block)
        self.blocks_by_hash[block.hash()] = block

        # The core rule of Bitcoin/longest chain consensus
        if block.height > self.current_height():
            self.tip_hash = block.hash()
            self._rebuild_canonical_index()
            print(f"[blockchain] adopted new LONGEST tip at height {block.height} {block.hash().hex()}")
            return True

        return False

    def _rebuild_canonical_index(self) -> None:
        new_index: dict[int, bytes] = {}
        current = self.blocks_by_hash[self.tip_hash]
        while True:
            new_index[current.height] = current.hash()
            if current.height == 0:
                break
            current = self.blocks_by_hash[current.header.prev_hash]
        self.blocks_by_height = new_index

    async def _mine_header(self, header: BlockHeader) -> BlockHeader:
        nonce = header.nonce
        while True:
            candidate = BlockHeader(
                prev_hash=header.prev_hash,
                txs_hash=header.txs_hash,
                timestamp=header.timestamp,
                difficulty=header.difficulty,
                nonce=nonce,
            )
            if has_leading_zero_bits(candidate.hash(), candidate.difficulty):
                return candidate
            nonce += 1
            if nonce % 10000 == 0:
                await asyncio.sleep(0)

    async def consensus_loop(self) -> None:
        if TEST_MODE:
            await self.try_submit_transaction_test()

        # All peers can now compete to mine simultaneously
        txs: tuple[bytes, ...]
        mined_nonempty = False

        if self.mempool:
            tx_hash, _transaction = next(iter(self.mempool.items()))
            txs = (tx_hash,)
            mined_nonempty = True
        elif self.blocks_since_last_nonempty < self.empty_blocks_after_transaction and self.current_height() > 0:
            txs = ()
        else:
            return

        parent = self.current_tip()
        header = BlockHeader(
            prev_hash=parent.hash(),
            txs_hash=compute_txs_hash(txs),
            timestamp=max(int(time.time()), parent.header.timestamp + 1),
            difficulty=DIFFICULTY,
            nonce=0,
        )

        print(f"[blockchain] mining block at height {parent.height + 1} with {len(txs)} tx")
        solved_header = await self._mine_header(header)
        block = Block(height=parent.height + 1, header=solved_header, tx_hashes=txs)
        
        # Check if someone else won the race while we were mining this block
        if block.header.prev_hash != self.tip_hash:
             print("[blockchain] Tip changed while mining, abandoning current candidate block.")
             return

        adopted = self._adopt_block(block)
        if not adopted:
            return

        if mined_nonempty:
            self.blocks_since_last_nonempty = 0
        else:
            self.blocks_since_last_nonempty += 1

        self._drop_confirmed_transactions()
        self._announce_block(block)

    async def sync_loop(self) -> None:
        # Every node should sync from others to learn about longer chains
        teammates = self.teammate_peers()
        if not teammates:
            return
            
        # Poll a random teammate to discover forks or alternative longer paths
        target_peer = random.choice(teammates)

        try:
            height_response = await self.request_chain_height(target_peer)
        except Exception:
            return

        if height_response.height <= self.current_height():
            return

        # Fetch blocks sequentially to evaluate the structural integrity of their chain
        for height in range(self.current_height() + 1, height_response.height + 1):
            try:
                response = await self.request_block(target_peer, height)
                block = self._payload_to_block(response)
                self._adopt_block(block)
                self._drop_confirmed_transactions()
            except Exception as exc:
                print(f"[blockchain] sync failed at height {height}: {exc}")
                break

    def _announce_block(self, block: Block) -> None:
        payload = self._build_block_payload(block, BlockchainAnnounceBlockPayload)
        for peer in self.teammate_peers():
            self.ez_send(peer, payload)

    def _drop_confirmed_transactions(self) -> None:
        # Re-evaluate mempool contents based on the current active canonical chain path.
        # This prevents transaction loss during chain reorganizations (reorgs).
        confirmed = set()
        current = self.current_tip()
        while current.height > 0:
            for tx_hash in current.tx_hashes:
                confirmed.add(tx_hash)
            current = self.blocks_by_hash[current.header.prev_hash]
            
        # Rebuild clean mempool: everything we know about minus what is confirmed on the main chain branch
        self.mempool = {
            tx_hash: tx for tx_hash, tx in self.known_transactions.items() if tx_hash not in confirmed
        }

    async def request_chain_height(self, peer: Peer) -> BlockchainGetChainHeightResponsePayload:
        request_id = next(self.pending_request_ids)
        future: asyncio.Future[BlockchainGetChainHeightResponsePayload] = asyncio.get_running_loop().create_future()
        self.pending_height_requests[request_id] = future
        self.ez_send(peer, BlockchainGetChainHeightPayload(request_id))
        try:
            return await asyncio.wait_for(future, timeout=5.0)
        finally:
            self.pending_height_requests.pop(request_id, None)

    async def request_block(self, peer: Peer, height: int) -> BlockchainGetBlockResponsePayload:
        future: asyncio.Future[BlockchainGetBlockResponsePayload] = asyncio.get_running_loop().create_future()
        self.pending_block_requests[height] = future
        self.ez_send(peer, BlockchainGetBlockPayload(height))
        try:
            return await asyncio.wait_for(future, timeout=5.0)
        finally:
            self.pending_block_requests.pop(height, None)

    async def try_submit_transaction_test(self) -> None:
        if self.current_height() > 0:
            return

        sender_key = self.my_peer.public_key.key_to_bin()
        data = f"Transaction {self.current_height()}".encode()
        timestamp = int(time.time())
        message = sender_key + data + u64_be(timestamp)
        signature = self.my_peer.key.signature(message)

        await self.on_submit_transaction_impl(
            self.my_peer,
            BlockchainSubmitTransactionPayload(sender_key, data, timestamp, signature),
            lambda _response_payload: None,
        )

    @lazy_wrapper(BlockchainSubmitTransactionPayload)
    async def on_submit_transaction(self, peer: Peer, payload: BlockchainSubmitTransactionPayload) -> None:
        await self.on_submit_transaction_impl(peer, payload, lambda response_payload: self.ez_send(peer, response_payload))

    async def on_submit_transaction_impl(
        self,
        peer: Peer,
        payload: BlockchainSubmitTransactionPayload,
        resp: Callable[[BlockchainSubmitTransactionResponsePayload], Any],
    ) -> None:
        transaction = Transaction(payload.sender_key, payload.data, payload.timestamp, payload.signature)
        tx_hash = transaction.tx_hash()

        print(
            f"[blockchain] got transaction from {peer} tx={tx_hash.hex()} timestamp={payload.timestamp}"
        )

        if not transaction.verify_signature():
            await await_if_necessary(
                resp(BlockchainSubmitTransactionResponsePayload(False, tx_hash, "invalid signature"))
            )
            return

        if tx_hash not in self.known_transactions:
            self.known_transactions[tx_hash] = transaction
            self.mempool[tx_hash] = transaction

            # Gossip (flood-fill) the transaction out to all teammate nodes so everyone can mine it
            for teammate in self.teammate_peers():
                if self.peer_key_hex(teammate) != self.peer_key_hex(peer):
                    self.ez_send(teammate, payload)

        await await_if_necessary(
            resp(BlockchainSubmitTransactionResponsePayload(True, tx_hash, "transaction accepted"))
        )

    @lazy_wrapper(BlockchainGetChainHeightPayload)
    async def on_get_chain_height(self, peer: Peer, payload: BlockchainGetChainHeightPayload) -> None:
        await self.on_get_chain_height_impl(peer, payload, lambda response_payload: self.ez_send(peer, response_payload))

    async def on_get_chain_height_impl(
        self,
        peer: Peer,
        payload: BlockchainGetChainHeightPayload,
        resp: Callable[[BlockchainGetChainHeightResponsePayload], Any],
    ) -> None:
        await await_if_necessary(
            resp(BlockchainGetChainHeightResponsePayload(payload.request_id, self.current_height(), self.tip_hash))
        )

    @lazy_wrapper(BlockchainGetBlockPayload)
    async def on_get_block(self, peer: Peer, payload: BlockchainGetBlockPayload) -> None:
        await self.on_get_block_impl(peer, payload, lambda response_payload: self.ez_send(peer, response_payload))

    async def on_get_block_impl(
        self,
        peer: Peer,
        payload: BlockchainGetBlockPayload,
        resp: Callable[[BlockchainGetBlockResponsePayload], Any],
    ) -> None:
        block = self._find_block_at_height(payload.height)
        if block is None:
            print(f"[blockchain] unknown block height requested {payload.height}")
            return

        await await_if_necessary(resp(self._build_block_payload(block, BlockchainGetBlockResponsePayload)))

    @lazy_wrapper(BlockchainSubmitTransactionResponsePayload)
    async def on_submit_transaction_response(self, peer: Peer, payload: BlockchainSubmitTransactionResponsePayload) -> None:
        await self.on_submit_transaction_response_impl(peer, payload)

    async def on_submit_transaction_response_impl(
        self,
        peer: Peer,
        payload: BlockchainSubmitTransactionResponsePayload,
    ) -> None:
        print(
            f"[blockchain] transaction response from {peer} success={payload.success} tx={payload.tx_hash.hex()} msg={payload.message}"
        )

    @lazy_wrapper(BlockchainGetChainHeightResponsePayload)
    async def on_get_chain_height_response(self, peer: Peer, payload: BlockchainGetChainHeightResponsePayload) -> None:
        future = self.pending_height_requests.get(payload.request_id)
        if future is not None and not future.done():
            future.set_result(payload)
            return
        await self.on_get_chain_height_response_impl(peer, payload)

    async def on_get_chain_height_response_impl(
        self,
        peer: Peer,
        payload: BlockchainGetChainHeightResponsePayload,
    ) -> None:
        print(
            f"[blockchain] chain height response from {peer} request={payload.request_id} height={payload.height} tip={payload.tip_hash.hex()}"
        )

    @lazy_wrapper(BlockchainGetBlockResponsePayload)
    async def on_get_block_response(self, peer: Peer, payload: BlockchainGetBlockResponsePayload) -> None:
        future = self.pending_block_requests.get(payload.height)
        if future is not None and not future.done():
            future.set_result(payload)
            return
        await self.on_get_block_response_impl(peer, payload)

    async def on_get_block_response_impl(self, peer: Peer, payload: BlockchainGetBlockResponsePayload) -> None:
        print(
            f"[blockchain] block response from {peer} height={payload.height} hash={payload.block_hash.hex()} prev={payload.prev_hash.hex()}"
        )

    @lazy_wrapper(BlockchainAnnounceBlockPayload)
    async def on_announce_block(self, peer: Peer, payload: BlockchainAnnounceBlockPayload) -> None:
        try:
            block = self._payload_to_block(payload)
            self._adopt_block(block)
            self._drop_confirmed_transactions()
        except Exception as exc:
            print(f"[blockchain] rejected block from {peer}: {exc}")


async def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--key", default="assignmentskey.pem")
    parser.add_argument("--port", type=int, default=8091)
    parser.add_argument("--group-id", dest="group_id", help="your lab 2 group id")
    parser.add_argument("--register", action="store_true", default=False)
    parser.add_argument("--test-mode", action="store_true", default=False)
    parser.add_argument(
        "--member-key",
        action="append",
        dest="member_keys",
        help="pass exactly 3 member public keys in registration order",
    )
    args = parser.parse_args()

    if args.test_mode:
        global TEST_MODE
        TEST_MODE = True

    raw_member_keys = args.member_keys if args.member_keys is not None else TEAM_MEMBER_KEYS_HEX
    member_keys_hex = resolve_member_keys(raw_member_keys)
    group_id = load_group_id(args.group_id)

    builder = ConfigBuilder().clear_keys().clear_overlays()
    builder.add_key("lab3key", "curve25519", args.key)
    builder.set_port(args.port)
    if args.register:
        builder.add_overlay(
            "Lab3GlobalCommunity",
            "lab3key",
            [
                WalkerDefinition(Strategy.RandomWalk, -1, {}),
                WalkerDefinition(Strategy.EdgeWalk, -1, {}),
            ],
            default_bootstrap_defs,
            {},
            [("started",)],
        )
    builder.add_overlay(
        "Lab3BlockchainCommunity",
        "lab3key",
        [
            WalkerDefinition(Strategy.RandomWalk, -1, {}),
            WalkerDefinition(Strategy.EdgeWalk, -1, {}),
        ],
        default_bootstrap_defs,
        {},
        [("started",)],
    )

    ipv8 = IPv8(
        builder.finalize(),
        extra_communities={
            "Lab3GlobalCommunity": Lab3GlobalCommunity,
            "Lab3BlockchainCommunity": Lab3BlockchainCommunity,
        },
    )
    await ipv8.start()

    global_overlay = next((overlay for overlay in ipv8.overlays if isinstance(overlay, Lab3GlobalCommunity)), None)
    blockchain_overlay = next(
        overlay for overlay in ipv8.overlays if isinstance(overlay, Lab3BlockchainCommunity)
    )

    if global_overlay is not None:
        global_overlay.configure(member_keys_hex, group_id)
    blockchain_overlay.configure(member_keys_hex)

    local_key_hex = blockchain_overlay.my_peer.public_key.key_to_bin().hex()
    if local_key_hex not in member_keys_hex:
        await ipv8.stop()
        raise ValueError("local key is not one of the 3 member keys")

    print("ipv8 started for lab 3")
    print(f"my public key {local_key_hex}")
    print("[blockchain] Every node configured to simultaneously compete and mine blocks.")

    try:
        if global_overlay is not None:
            await global_overlay.done.wait()
        await blockchain_overlay.done.wait()
    finally:
        await ipv8.stop()

    if global_overlay is not None and global_overlay.error:
        raise RuntimeError(global_overlay.error)
    if blockchain_overlay.error:
        raise RuntimeError(blockchain_overlay.error)


if __name__ == "__main__":
    asyncio.run(main())