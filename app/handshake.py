import binascii
import socket
from dataclasses import dataclass
from app.peers import parse_peers, request_tracker
from app.torrent import decode_torrent
from app.peers import parse_peers
@dataclass
class PeerProtocol:
    # length of the protocol string (BitTorrent protocol) which is 19 (1 byte)
    length = 19
    # the string BitTorrent protocol (19 bytes)
    protocol = b"BitTorrent protocol"
    # eight reserved bytes, which are all set to zero (8 bytes)
    reserved_bytes: bytes
    # sha1 infohash (20 bytes) (NOT the hexadecimal representation, which is 40 bytes long)
    # sha1 info hash (20 bytes) (NOT the hexadecimal representation, which is 40 bytes long)
    info_hash: bytes
    # peer id(20 bytes) (generate 20 random byte values)
    peer_id = b"a" * 20
    def serialize_to_message(self):
        msg = bytearray()
        msg.append(self.length)
        msg.extend(self.protocol)
        msg.extend(self.reserved_bytes)
        msg.extend(self.info_hash)
        msg.extend(self.peer_id)
        return msg
    # print(msg)
def _handshake(file_name, peer=None):
    t = decode_torrent(file_name)
    if not peer:
        peer_ip, peer_port = parse_peers(t)[0]
    else:
        peer_ip, peer_port = peer.split(":")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((peer_ip, int(peer_port)))
    p = PeerProtocol(reserved_bytes=bytearray(8), info_hash=t.info_hash.digest())
    s.send(p.serialize_to_message())
    print(f"Peer ID: {s.recv(68)[48:].hex()}")
def magnet_handshake(tracker_url, info_hash: str):
    info_hash = binascii.unhexlify(info_hash)
    assert len(info_hash) == 20
    peers = request_tracker(tracker_url, info_hash)
    peer_ip, peer_port = peers[0]
    print(peer_ip, peer_port)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((peer_ip, int(peer_port)))
    reserved_bytes = (1 << 20).to_bytes(8, "big")
    p = PeerProtocol(reserved_bytes=reserved_bytes, info_hash=info_hash)
    s.send(p.serialize_to_message())
    print(f"Peer ID: {s.recv(68)[48:].hex()}")