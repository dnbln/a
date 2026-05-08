import base64
import os
from asyncio import run

from ipv8 import peer
from ipv8.community import Community
from ipv8.configuration import ConfigBuilder, Strategy, WalkerDefinition, default_bootstrap_defs
from ipv8.messaging.payload import IntroductionResponsePayload, NewIntroductionResponsePayload
from ipv8.messaging.payload_headers import GlobalTimeDistributionPayload
from ipv8.peer import Peer
from ipv8.peerdiscovery.network import PeerObserver
from ipv8.util import run_forever
from ipv8_service import IPv8


class MyCommunity(Community, PeerObserver):
    # Register this community with a randomly generated community ID.
    # Other peers will connect to this community based on this identifier.
    community_id = bytes.fromhex("2c1cc6e35ff484f99ebdfb6108477783c0102881")
    src_id = bytes.fromhex("4c69624e61434c504b3a86b23934a28d669c390e2d1fc0b0870706c4591cc0cb178bc5a811da6d87d27ef319b2638ef60cc8d119724f4c53a1ebfad919c3ac4136c501ce5c09364e0ebb")


    def on_peer_added(self, peer: Peer) -> None:
        print("I am:", self.my_peer, "I found:", peer)

    
    def introduction_response_callback(self, peer: Peer, dist: GlobalTimeDistributionPayload,
                                       payload: IntroductionResponsePayload | NewIntroductionResponsePayload) -> None:
        print("Received introduction response from peer %s with distribution %s and payload %s" % (peer, dist, payload))

        bin = peer.key.pub().key_to_bin()
        # print("Peer public key: %s" % bin.hex())

        print("Peer public key: %s" % bytes.hex(bin))
        print("src_id: %s" % bytes.hex(self.src_id))
        if bin != self.src_id:
            print("Public key does not match src_id, refusing to proceed!")
            return
        print("Public key matches src_id, proceeding with connection!")

    def on_peer_removed(self, peer: Peer) -> None:
        pass

    def started(self) -> None:
        print("Community started, my peer is %s" % self.my_peer)
        self.network.add_peer_observer(self)




async def start_communities() -> None:
    builder = ConfigBuilder().clear_keys().clear_overlays()
    builder.add_key("my peer", "medium", "key.pem")
    # Instruct IPv8 to load our custom overlay, registered in _COMMUNITIES.
    # We use the "my peer" key, which we registered before.
    # We will attempt to find other peers in this overlay using the
    # RandomWalk strategy, until we find 10 peers.
    # We do not provide additional startup arguments or a function to run
    # once the overlay has been initialized.
    builder.add_overlay("MyCommunity", "my peer",
                        [WalkerDefinition(Strategy.RandomWalk,
                                            -1, {}),
                        WalkerDefinition(Strategy.EdgeWalk,
                                            -1, {}),
                                            ],
                        default_bootstrap_defs, {}, [])
    await IPv8(builder.finalize(),
                extra_communities={"MyCommunity": MyCommunity}).start()
    await run_forever()


run(start_communities())