import socket
from dataclasses import dataclass
from app.handshake import PeerProtocol
from app.peers import parse_peers
from app.torrent import decode_torrent, parse_hashes
SIZE = 1 << 14
@dataclass()
class PayloadMessage:
    # index: the zero-based piece index
    index: int
    # begin: the zero-based byte offset within the piece
    begin: int
    # block: the data for the piece, usually 2^14 bytes long
    block: bytes
# Peer messages consist of a message length prefix (4 bytes)
# message id (1 byte) and a payload (variable size).
@dataclass
class PeerMessage:
    length: int
    message_id: int
    pay_load: bytes
def deserialize_peer_message(length: int, message: bytes):
    return PeerMessage(
        length=length,
        message_id=int.from_bytes(message[0:1], "big"),
        pay_load=message,
    )
def serialize_peer_message(p: PeerMessage) -> bytes:
    msg = bytearray()
    msg.extend(p.length.to_bytes(4, "big"))
    msg.extend(p.message_id.to_bytes(1, "big"))
    msg.extend(p.pay_load)
    return msg
def receive_message(s):
    length = s.recv(4)
    while not length or not int.from_bytes(length):
        length = s.recv(4)
    length = int.from_bytes(length)
    print(f"receive length: {length}")
    message = s.recv(length)
    while len(message) < length:
        message += s.recv(length - len(message))
    return length, message
def download_piece(flag, save_path, file_name, piece_index: int, peer=None):
    t = decode_torrent(file_name)
    if not peer:
        peer_ip, peer_port = parse_peers(t)[0]
    else:
        peer_ip, peer_port = peer.split(":")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((peer_ip, int(peer_port)))
        # handshake
        p = PeerProtocol(reserved_bytes=bytearray(8), info_hash=t.info_hash.digest())
        s.send(p.serialize_to_message())
        print(f"Peer ID: {s.recv(68)[48:].hex()}")
        # bitfield message
        while 1:
            length, message = receive_message(s)
            bitfield_msg = deserialize_peer_message(length, message)
            print(f"waiting for bitfield message: {bitfield_msg}")
            # The message id for this message type is 5.
            if bitfield_msg.message_id == 5:
                break
        interested_msg = PeerMessage(length=1, message_id=2, pay_load=bytes())
        print(f"sending interested message: {interested_msg}")
        s.send(serialize_peer_message(interested_msg))
        while True:
            length, message = receive_message(s)
            unchoke_msg = deserialize_peer_message(length, message)
            print(f"waiting for unchoke message: {unchoke_msg}")
            if unchoke_msg.message_id == 1:
                break
        t = decode_torrent(file_name)
        file_length = t.length
        piece_count = len(parse_hashes(t))
        default_piece_length = t.piece_length
        if piece_index == piece_count - 1:
            piece_length = file_length - (default_piece_length * piece_index)
        else:
            piece_length = default_piece_length
        print(file_length, piece_count, piece_length)
        count = (piece_length + SIZE - 1) // SIZE
        for i in range(count):
            pay_load = bytearray()
            # index
            pay_load.extend(piece_index.to_bytes(4, "big"))
            # begin
            pay_load.extend((i << 14).to_bytes(4, "big"))
            # length
            block_length = min(SIZE, piece_length - (i << 14))
            pay_load.extend(block_length.to_bytes(4, "big"))
            print(f"Requesting block {i} of {count} with length {block_length}")
            msg = PeerMessage(1 + len(pay_load), message_id=6, pay_load=pay_load)
            s.send(serialize_peer_message(msg))
            # print(f"sending request message {msg}")
            length, message = receive_message(s)
            msg = deserialize_peer_message(length, message)
            assert msg.message_id == 7
            block = msg.pay_load[9:]  # (id:1, index:4, begin:4)
            with open(save_path, "ab") as f:
                f.write(block)