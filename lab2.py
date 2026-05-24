import argparse
import asyncio
from dataclasses import dataclass, field
from typing import Sequence

from ipv8.community import Community, CommunitySettings
from ipv8.configuration import ConfigBuilder, Strategy, WalkerDefinition, default_bootstrap_defs
from ipv8.keyvault.crypto import default_eccrypto
from ipv8.lazy_community import lazy_wrapper
from ipv8.messaging.payload import Payload
from ipv8.peer import Peer
from ipv8.peerdiscovery.network import PeerObserver
from ipv8_service import IPv8


LAB2_COMMUNITY_ID = bytes.fromhex("4c61623247726f75705369676e696e6732303236")
LAB2_SERVER_PUBLIC_KEY_HEX = (
    "4c69624e61434c504b3a82e33614a342774e084af80835838d6dbdb64a537d3d"
    "db6c1d82011a7f101553cda40cf5fa0e0fc23abd0a9c4f81322282c5b34566f6"
    "b8401f5f683031e60c96"
)

TEAM_MEMBER_KEYS_HEX = [
    "4c69624e61434c504b3ae46676ba012e13d7e989930de441c5c74387a43d9b4c6d6f5037c783fa657c416a7791a2b1d45529e6804900465ec1608d64930f43f91b7c282fdec7b442d609",
    "4c69624e61434c504b3ab5d5fb13bc9a5a7c03efce411b71fa033e1f64aa9b2bacf672760c9991800c3c1e9088b94ce570f9c0e9dae8537014b84086b22ac1e5570b6d15e7f972574c29",
    "4c69624e61434c504b3a62250a7fcf0e526d3b228691b882a2bee18163907b3426d3e7c61e6c2474337212d86226da9d3e51dc82cf56491b0b171db113dd6f6a1147f938118a5dbae781",
]

SUBMIT_ORDER = [1, 2, 3]


class RegisterPayload(Payload):
    msg_id = 1
    format_list = ["varlenH", "varlenH", "varlenH"]

    def __init__(self, member1_key: bytes, member2_key: bytes, member3_key: bytes) -> None:
        self.member1_key = member1_key
        self.member2_key = member2_key
        self.member3_key = member3_key

    def to_pack_list(self):
        return [
            ("varlenH", self.member1_key),
            ("varlenH", self.member2_key),
            ("varlenH", self.member3_key),
        ]

    @classmethod
    def from_unpack_list(cls, member1_key: bytes, member2_key: bytes, member3_key: bytes):
        return cls(member1_key, member2_key, member3_key)


class RegistrationResponsePayload(Payload):
    msg_id = 2
    format_list = ["?", "varlenHutf8", "varlenHutf8"]

    def __init__(self, success: bool, group_id: str, message: str) -> None:
        self.success = success
        self.group_id = group_id
        self.message = message

    def to_pack_list(self):
        return [
            ("?", self.success),
            ("varlenHutf8", self.group_id),
            ("varlenHutf8", self.message),
        ]

    @classmethod
    def from_unpack_list(cls, success: bool, group_id: str, message: str):
        return cls(success, group_id, message)


class ChallengeRequestPayload(Payload):
    msg_id = 3
    format_list = ["varlenHutf8"]

    def __init__(self, group_id: str) -> None:
        self.group_id = group_id

    def to_pack_list(self):
        return [("varlenHutf8", self.group_id)]

    @classmethod
    def from_unpack_list(cls, group_id: str):
        return cls(group_id)


class ChallengeResponsePayload(Payload):
    msg_id = 4
    format_list = ["varlenH", "q", "d"]

    def __init__(self, nonce: bytes, round_number: int, deadline: float) -> None:
        self.nonce = nonce
        self.round_number = round_number
        self.deadline = deadline

    def to_pack_list(self):
        return [
            ("varlenH", self.nonce),
            ("q", self.round_number),
            ("d", self.deadline),
        ]

    @classmethod
    def from_unpack_list(cls, nonce: bytes, round_number: int, deadline: float):
        return cls(nonce, round_number, deadline)


class SignatureBundlePayload(Payload):
    msg_id = 5
    format_list = ["varlenHutf8", "q", "varlenH", "varlenH", "varlenH"]

    def __init__(
        self,
        group_id: str,
        round_number: int,
        sig1: bytes,
        sig2: bytes,
        sig3: bytes,
    ) -> None:
        self.group_id = group_id
        self.round_number = round_number
        self.sig1 = sig1
        self.sig2 = sig2
        self.sig3 = sig3

    def to_pack_list(self):
        return [
            ("varlenHutf8", self.group_id),
            ("q", self.round_number),
            ("varlenH", self.sig1),
            ("varlenH", self.sig2),
            ("varlenH", self.sig3),
        ]

    @classmethod
    def from_unpack_list(
        cls,
        group_id: str,
        round_number: int,
        sig1: bytes,
        sig2: bytes,
        sig3: bytes,
    ):
        return cls(group_id, round_number, sig1, sig2, sig3)


class RoundResultPayload(Payload):
    msg_id = 6
    format_list = ["?", "q", "q", "varlenHutf8"]

    def __init__(
        self,
        success: bool,
        round_number: int,
        rounds_completed: int,
        message: str,
    ) -> None:
        self.success = success
        self.round_number = round_number
        self.rounds_completed = rounds_completed
        self.message = message

    def to_pack_list(self):
        return [
            ("?", self.success),
            ("q", self.round_number),
            ("q", self.rounds_completed),
            ("varlenHutf8", self.message),
        ]

    @classmethod
    def from_unpack_list(
        cls,
        success: bool,
        round_number: int,
        rounds_completed: int,
        message: str,
    ):
        return cls(success, round_number, rounds_completed, message)


class NoncePayload(Payload):
    msg_id = 10
    format_list = ["varlenHutf8", "q", "varlenH"]

    def __init__(self, group_id: str, round_number: int, nonce: bytes) -> None:
        self.group_id = group_id
        self.round_number = round_number
        self.nonce = nonce

    def to_pack_list(self):
        return [
            ("varlenHutf8", self.group_id),
            ("q", self.round_number),
            ("varlenH", self.nonce),
        ]

    @classmethod
    def from_unpack_list(cls, group_id: str, round_number: int, nonce: bytes):
        return cls(group_id, round_number, nonce)


class SignatureSharePayload(Payload):
    msg_id = 11
    format_list = ["varlenHutf8", "q", "varlenH"]

    def __init__(self, group_id: str, round_number: int, signature: bytes) -> None:
        self.group_id = group_id
        self.round_number = round_number
        self.signature = signature

    def to_pack_list(self):
        return [
            ("varlenHutf8", self.group_id),
            ("q", self.round_number),
            ("varlenH", self.signature),
        ]

    @classmethod
    def from_unpack_list(cls, group_id: str, round_number: int, signature: bytes):
        return cls(group_id, round_number, signature)


class RoundDonePayload(Payload):
    msg_id = 12
    format_list = ["varlenHutf8", "q"]

    def __init__(self, group_id: str, rounds_completed: int) -> None:
        self.group_id = group_id
        self.rounds_completed = rounds_completed

    def to_pack_list(self):
        return [
            ("varlenHutf8", self.group_id),
            ("q", self.rounds_completed),
        ]

    @classmethod
    def from_unpack_list(cls, group_id: str, rounds_completed: int):
        return cls(group_id, rounds_completed)


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


@dataclass
class ActiveRound:
    round_number: int
    nonce: bytes
    signatures: dict[int, bytes] = field(default_factory=dict)
    bundle_sent: bool = False


class Lab2Community(Community, PeerObserver):
    community_id = LAB2_COMMUNITY_ID

    def __init__(self, settings: CommunitySettings) -> None:
        super().__init__(settings)

        self.add_message_handler(RegistrationResponsePayload, self.on_registration_response)
        self.add_message_handler(ChallengeResponsePayload, self.on_challenge_response)
        self.add_message_handler(RoundResultPayload, self.on_round_result)
        self.add_message_handler(NoncePayload, self.on_nonce)
        self.add_message_handler(SignatureSharePayload, self.on_signature_share)
        self.add_message_handler(RoundDonePayload, self.on_round_done)

        self.member_keys_hex: list[str] = []
        self.group_id: str | None = None
        self.registration_sent = False
        self.current_round = 1
        self.active_round: ActiveRound | None = None
        self.done = asyncio.Event()
        self.error: str | None = None

    def started(self) -> None:
        self.network.add_peer_observer(self)
        self.register_task("lab2_loop", self.loop, interval=0.3, delay=0.0)

    def configure(self, member_keys_hex: Sequence[str]) -> None:
        self.member_keys_hex = list(member_keys_hex)

    def on_peer_added(self, peer: Peer) -> None:
        key_hex = peer.public_key.key_to_bin().hex()
        if key_hex == LAB2_SERVER_PUBLIC_KEY_HEX:
            print("Found verified server.")
        elif key_hex in self.member_keys_hex:
            print(f"Found teammate: {key_hex}")

    def on_peer_removed(self, peer: Peer) -> None:
        pass

    def is_server(self, peer: Peer) -> bool:
        return peer.public_key.key_to_bin().hex() == LAB2_SERVER_PUBLIC_KEY_HEX

    def member_index_for_key(self, key_hex: str) -> int | None:
        try:
            return self.member_keys_hex.index(key_hex) + 1
        except ValueError:
            return None

    def member_index_for_peer(self, peer: Peer) -> int | None:
        return self.member_index_for_key(peer.public_key.key_to_bin().hex())

    def local_member_index(self) -> int:
        member_index = self.member_index_for_key(self.my_peer.public_key.key_to_bin().hex())
        if member_index is None:
            raise ValueError("Local key is not one of the configured group members.")
        return member_index

    def expected_submitter(self, round_number: int) -> int:
        return SUBMIT_ORDER[round_number - 1]

    def is_local_submitter(self) -> bool:
        return self.local_member_index() == self.expected_submitter(self.current_round)

    def server_peer(self) -> Peer | None:
        for peer in self.get_peers():
            if self.is_server(peer):
                return peer
        return None

    def teammate_peer(self, member_index: int) -> Peer | None:
        member_key_hex = self.member_keys_hex[member_index - 1]
        for peer in self.get_peers():
            if peer.public_key.key_to_bin().hex() == member_key_hex:
                return peer
        return None

    def sign(self, nonce: bytes) -> bytes:
        return self.my_peer.key.signature(nonce)

    def verify_share(self, member_index: int, nonce: bytes, signature: bytes) -> bool:
        public_key = default_eccrypto.key_from_public_bin(bytes.fromhex(self.member_keys_hex[member_index - 1]))
        try:
            public_key.verify(signature, nonce)
        except Exception:
            return False
        return True

    async def loop(self) -> None:
        if self.done.is_set():
            return

        if self.group_id is None:
            await self.try_register()
            return

        if self.current_round > 3:
            self.done.set()
            return

        if not self.is_local_submitter():
            return

        if self.active_round is None:
            await self.request_challenge()
            return

        if len(self.active_round.signatures) == 3 and not self.active_round.bundle_sent:
            await self.submit_bundle()

    async def try_register(self) -> None:
        if self.registration_sent:
            return

        server = self.server_peer()
        if server is None:
            return

        member_keys = [bytes.fromhex(key) for key in self.member_keys_hex]
        self.ez_send(server, RegisterPayload(*member_keys))
        self.registration_sent = True
        print("Sent registration.")

    async def request_challenge(self) -> None:
        server = self.server_peer()
        if server is None or self.group_id is None:
            return

        self.ez_send(server, ChallengeRequestPayload(self.group_id))
        print(f"Requested challenge for round {self.current_round}.")

    async def send_nonce_to_teammates(self) -> None:
        if self.active_round is None or self.group_id is None:
            return

        payload = NoncePayload(self.group_id, self.active_round.round_number, self.active_round.nonce)
        for member_index in (1, 2, 3):
            if member_index == self.local_member_index():
                continue
            peer = self.teammate_peer(member_index)
            if peer is not None:
                self.ez_send(peer, payload)

    async def send_signature_to_submitter(self, round_number: int, nonce: bytes) -> None:
        if self.group_id is None:
            return

        submitter = self.expected_submitter(round_number)
        peer = self.teammate_peer(submitter)
        if peer is None:
            return

        self.ez_send(peer, SignatureSharePayload(self.group_id, round_number, self.sign(nonce)))

    async def submit_bundle(self) -> None:
        if self.active_round is None or self.group_id is None:
            return

        server = self.server_peer()
        if server is None:
            return

        sig1 = self.active_round.signatures[1]
        sig2 = self.active_round.signatures[2]
        sig3 = self.active_round.signatures[3]
        payload = SignatureBundlePayload(
            self.group_id,
            self.active_round.round_number,
            sig1,
            sig2,
            sig3,
        )
        self.ez_send(server, payload)
        self.active_round.bundle_sent = True
        print(f"Submitted bundle for round {self.active_round.round_number}.")

    async def announce_round_done(self, rounds_completed: int) -> None:
        if self.group_id is None:
            return

        payload = RoundDonePayload(self.group_id, rounds_completed)
        for member_index in (1, 2, 3):
            if member_index == self.local_member_index():
                continue
            peer = self.teammate_peer(member_index)
            if peer is not None:
                self.ez_send(peer, payload)

    def set_active_round(self, round_number: int, nonce: bytes) -> None:
        if self.active_round is not None and self.active_round.round_number == round_number:
            return

        self.active_round = ActiveRound(round_number, nonce)
        self.active_round.signatures[self.local_member_index()] = self.sign(nonce)
        print(f"Started round {round_number}.")

    @lazy_wrapper(RegistrationResponsePayload)
    def on_registration_response(self, peer: Peer, payload: RegistrationResponsePayload) -> None:
        if not self.is_server(peer):
            return

        print(payload.message)
        if not payload.success:
            self.error = payload.message
            self.done.set()
            return

        self.group_id = payload.group_id
        print(f"group_id = {self.group_id}")

    @lazy_wrapper(ChallengeResponsePayload)
    def on_challenge_response(self, peer: Peer, payload: ChallengeResponsePayload) -> None:
        if not self.is_server(peer):
            return

        if payload.round_number != self.current_round:
            return

        if not self.is_local_submitter():
            return

        self.set_active_round(payload.round_number, payload.nonce)
        asyncio.create_task(self.send_nonce_to_teammates())

    @lazy_wrapper(NoncePayload)
    def on_nonce(self, peer: Peer, payload: NoncePayload) -> None:
        sender_index = self.member_index_for_peer(peer)
        if sender_index is None or self.group_id != payload.group_id:
            return

        if sender_index != self.expected_submitter(payload.round_number):
            return

        if payload.round_number != self.current_round:
            return

        self.set_active_round(payload.round_number, payload.nonce)
        if not self.is_local_submitter():
            asyncio.create_task(self.send_signature_to_submitter(payload.round_number, payload.nonce))

    @lazy_wrapper(SignatureSharePayload)
    def on_signature_share(self, peer: Peer, payload: SignatureSharePayload) -> None:
        sender_index = self.member_index_for_peer(peer)
        if sender_index is None or self.group_id != payload.group_id:
            return

        if not self.is_local_submitter():
            return

        if self.active_round is None or self.active_round.round_number != payload.round_number:
            return

        if not self.verify_share(sender_index, self.active_round.nonce, payload.signature):
            print(f"Invalid signature from member {sender_index}.")
            return

        self.active_round.signatures[sender_index] = payload.signature
        print(f"Collected signature from member {sender_index}.")

    @lazy_wrapper(RoundResultPayload)
    def on_round_result(self, peer: Peer, payload: RoundResultPayload) -> None:
        if not self.is_server(peer):
            return

        print(payload.message)
        if not payload.success:
            self.error = payload.message
            self.done.set()
            return

        self.current_round = payload.rounds_completed + 1
        self.active_round = None
        asyncio.create_task(self.announce_round_done(payload.rounds_completed))

        if payload.rounds_completed >= 3:
            self.done.set()

    @lazy_wrapper(RoundDonePayload)
    def on_round_done(self, peer: Peer, payload: RoundDonePayload) -> None:
        sender_index = self.member_index_for_peer(peer)
        if sender_index is None or self.group_id != payload.group_id:
            return

        finished_round = payload.rounds_completed
        if sender_index != self.expected_submitter(finished_round):
            return

        if payload.rounds_completed >= self.current_round:
            self.current_round = payload.rounds_completed + 1
            self.active_round = None
            print(f"Advanced to round {self.current_round}.")

        if payload.rounds_completed >= 3:
            self.done.set()


async def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--key", default="lab1_identity.pem")
    parser.add_argument("--port", type=int, default=8091)
    parser.add_argument(
        "--member-key",
        action="append",
        dest="member_keys",
        help="Pass exactly 3 member public keys in canonical registration order.",
    )
    args = parser.parse_args()

    raw_member_keys = args.member_keys if args.member_keys is not None else TEAM_MEMBER_KEYS_HEX
    member_keys_hex = resolve_member_keys(raw_member_keys)

    builder = ConfigBuilder().clear_keys().clear_overlays()
    builder.add_key("lab2key", "curve25519", args.key)
    builder.set_port(args.port)
    builder.add_overlay(
        "Lab2Community",
        "lab2key",
        [WalkerDefinition(Strategy.RandomWalk,
                                            -1, {}),
                        WalkerDefinition(Strategy.EdgeWalk,
                                            -1, {}),
                                            ],
        default_bootstrap_defs,
        {},
        [("started",)],
    )

    ipv8 = IPv8(builder.finalize(), extra_communities={"Lab2Community": Lab2Community})
    await ipv8.start()

    overlay = next(overlay for overlay in ipv8.overlays if isinstance(overlay, Lab2Community))
    overlay.configure(member_keys_hex)

    local_key_hex = overlay.my_peer.public_key.key_to_bin().hex()
    if local_key_hex not in member_keys_hex:
        await ipv8.stop()
        raise ValueError("Local key is not one of the 3 member keys.")

    print("IPv8 started for Lab 2.")
    print(f"My public key: {local_key_hex}")
    print("Member order:")
    for index, member_key in enumerate(member_keys_hex, start=1):
        print(f"  {index}. {member_key}")
    print(f"Submit order: {SUBMIT_ORDER}")

    try:
        await overlay.done.wait()
    finally:
        await ipv8.stop()

    if overlay.error:
        raise RuntimeError(overlay.error)


if __name__ == "__main__":
    asyncio.run(main())
