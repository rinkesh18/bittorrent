import hashlib
import math
import socket
import sys
from urllib.parse import unquote
import requests
SHA1_HASH_SIZE = 20
STD_BLOCK_SIZE = 16 * 1024
PEER_ID = "09724808973135933552"
class TorrentMetainfo:
    def __init__(self, metainfo: dict):
        self.tracker_url: str = metainfo["announce"].decode()
        self.info = metainfo["info"]
        self.length: int = self.info["length"]
        self.name: str = self.info["name"].decode()
        self.piece_length: int = self.info["piece length"]
        self.pieces: bytes = self.info["pieces"]
        self.piece_hashes: list[bytes] = [
            self.pieces[i : i + SHA1_HASH_SIZE]
            for i in range(0, len(self.pieces), SHA1_HASH_SIZE)
        ]
        bencoded_info = encode(metainfo["info"])
        self.info_hash: bytes = hashlib.sha1(bencoded_info).digest()
def encode(value) -> bytes:
    if type(value) is bytes:
        size = len(value)
        return f"{size}:".encode() + value
    elif type(value) is str:
        size = len(value)
        return f"{size}:{value}".encode()
    elif type(value) is int:
        return f"i{value}e".encode()
    elif type(value) is list:
        arr = [encode(v) for v in value]
        return b"l" + b"".join(arr) + b"e"
    elif type(value) is dict:
        arr = [encode(k) + encode(v) for k, v in value.items()]
        return b"d" + b"".join(arr) + b"e"
    else:
        raise NotImplementedError("[ENCODE] Not supported")
def decode_str(bencoded_value: bytes) -> tuple[bytes, int]:
    sep = bencoded_value.find(b":")
    if sep == -1:
        raise ValueError("Invalid encoded value for str")
    size = int(bencoded_value[:sep].decode())
    end = sep + size + 1
    value = bencoded_value[sep + 1 : end]
    return (value, end)
def decode_int(bencoded_value: bytes) -> tuple[int, int]:
    end = bencoded_value.find(b"e")
    if end == -1:
        raise ValueError("Invalid encoded value for int")
    value = int(bencoded_value[:end].decode())
    return (value, end + 1)
def decode_list(bencoded_value: bytes) -> tuple[list, int]:
    res = []
    i = 0
    while i < len(bencoded_value):
        first_byte = chr(bencoded_value[i])
        if first_byte.isdigit():
            value, end = decode_str(bencoded_value[i:])
            i += end
            res.append(value)
        elif first_byte in ["i", "l", "d"]:
            match first_byte:
                case "i":
                    value, end = decode_int(bencoded_value[i + 1 :])
                case "l":
                    value, end = decode_list(bencoded_value[i + 1 :])
                case "d":
                    value, end = decode_dict(bencoded_value[i + 1 :])
            i += end + 1
            res.append(value)
        elif first_byte == "e":
            i += 1
            break
        else:
            raise NotImplementedError("[DECODE LIST] Not supported")
    return (res, i)
def decode_dict(bencoded_value: bytes) -> tuple[dict, int]:
    arr, end = decode_list(bencoded_value)
    # Keys are always strings
    kvs = {arr[i].decode(): arr[i + 1] for i in range(0, len(arr), 2)}
    return (kvs, end + 1)
def decode(bencoded_value: bytes):
    value, _ = decode_list(bencoded_value)
    return value[0]
def display(value) -> str:
    if type(value) is bytes:
        return f'"{value.decode()}"'
    elif type(value) is str:
        return f'"{value}"'
    elif type(value) is int:
        return f"{value}"
    elif type(value) is list:
        arr = [display(v) for v in value]
        return "[" + ",".join(arr) + "]"
    elif type(value) is dict:
        kvs = [f"{display(k)}:{display(v)}" for k, v in value.items()]
        return "{" + ",".join(kvs) + "}"
    else:
        raise NotImplementedError("[DISLAY] Not supported")
def parse_torrent_file(file_name: str) -> TorrentMetainfo:
    with open(file_name, "rb") as f:
        metainfo: dict = decode(f.read())
        return TorrentMetainfo(metainfo)
def print_info(metainfo: TorrentMetainfo):
    print(f"Tracker URL: {metainfo.tracker_url}")
    print(f"Length: {metainfo.length}")
    print(f"Info Hash: {metainfo.info_hash.hex()}")
    print(f"Piece Length: {metainfo.piece_length}")
    print("Piece Hashes:")
    for piece_hash in metainfo.piece_hashes:
        print(f"{piece_hash.hex()}")
def fetch_peers(metainfo: TorrentMetainfo) -> list[tuple[str, int]]:
    query_params = {
        "info_hash": metainfo.info_hash,
        "peer_id": PEER_ID,
        "port": 6881,
        "uploaded": 0,
        "downloaded": 0,
        "left": metainfo.length,
        "compact": 1,
    }
    req = requests.get(metainfo.tracker_url, params=query_params)
    resp: dict = decode(req.content)
    peers_bytes: list[bytes] = [
        resp["peers"][i : i + 6] for i in range(0, len(resp["peers"]), 6)
    ]
    peers = []
    for pb in peers_bytes:
        ip, port = pb[0:4], pb[4:]
        ip_str = ".".join([str(n) for n in ip])
        port = int.from_bytes(port)
        peers.append((ip_str, port))
    return peers
def print_peers(metainfo: TorrentMetainfo):
    peers = fetch_peers(metainfo)
    for p in peers:
        print(f"{p[0]}:{p[1]}")
def get_socket(ip: str, port: int) -> socket.socket:
    s = socket.socket()
    print(f"Connecting to {ip}:{port}")
    s.connect((ip, int(port)))
    return s
def peer_handshake(metainfo: TorrentMetainfo, s: socket.socket) -> bytes:
    handshake = (
        (19).to_bytes(1)
        + b"BitTorrent protocol"
        + (0).to_bytes(8)
        + metainfo.info_hash
        + int(PEER_ID).to_bytes(20)
    )
    s.send(handshake)
    resp = s.recv(len(handshake))
    return resp
def recv_message(s: socket.socket) -> bytes:
    msg_len = int.from_bytes(s.recv(4))
    # print(f"Received message of length {msg_len}")
    msg = s.recv(msg_len)
    while len(msg) < msg_len:
        msg += s.recv(msg_len - len(msg))
    return msg
def setup_download(s: socket.socket):
    # Wait for bitfield message
    msg = recv_message(s)
    assert msg[0] == 5
    # Send interested message
    s.send((1).to_bytes(4) + (2).to_bytes(1))
    # Wait for unchoke message
    msg = recv_message(s)
    assert msg[0] == 1
def send_download_request(
    metainfo: TorrentMetainfo, s: socket.socket, piece_idx: int
) -> bytes:
    print(f"Downloading piece {piece_idx}")
    # Determine size of requested piece
    piece_size = metainfo.piece_length
    num_pieces = len(metainfo.piece_hashes)
    if piece_idx == num_pieces - 1:
        piece_size = metainfo.length - (piece_size * (num_pieces - 1))
    # Determine number of blocks making up the piece
    num_blocks = math.ceil(piece_size / STD_BLOCK_SIZE)
    # Send request messages for the piece blocks
    for b in range(num_blocks):
        # Smaller block size for last block
        block_size = STD_BLOCK_SIZE
        if b == num_blocks - 1:
            block_size = piece_size - (STD_BLOCK_SIZE * (num_blocks - 1))
        payload = (
            (piece_idx).to_bytes(4)
            + (b * STD_BLOCK_SIZE).to_bytes(4)
            + (block_size).to_bytes(4)
        )
        s.send((1 + len(payload)).to_bytes(4) + (6).to_bytes(1) + payload)
        # print(f"Sent request for piece {piece_idx} block {b}")
    # Wait for piece messages
    recv_blocks = []
    while len(recv_blocks) < num_blocks:
        msg = recv_message(s)
        assert msg[0] == 7
        begin = int.from_bytes(msg[5:9])
        block = msg[9:]
        # print(f"Received piece {p} block {begin // STD_BLOCK_SIZE}")
        recv_blocks.append((begin, block))
    # Create piece from blocks
    piece = b"".join([block for _, block in recv_blocks])
    # Verify piece hash
    assert hashlib.sha1(piece).digest() == metainfo.piece_hashes[piece_idx]
    return piece
def download_piece(metainfo: TorrentMetainfo, s: socket.socket, piece_idx: int):
    setup_download(s)
    return send_download_request(metainfo, s, piece_idx)
def main():
    command = sys.argv[1]
    match command:
        case "decode":
            bencoded_value = sys.argv[2].encode()
            print(display(decode(bencoded_value)))
        case "info":
            torrent_metainfo = parse_torrent_file(sys.argv[2])
            print_info(torrent_metainfo)
        case "peers":
            torrent_metainfo = parse_torrent_file(sys.argv[2])
            print_peers(torrent_metainfo)
        case "handshake":
            torrent_metainfo = parse_torrent_file(sys.argv[2])
            peer = sys.argv[3]
            ip, port = peer.split(":")
            s = get_socket(ip, int(port))
            handshake_resp = peer_handshake(torrent_metainfo, s)
            peer_id = handshake_resp[-20:]
            print(f"Peer ID: {peer_id.hex()}")
        case "download_piece":
            torrent_metainfo = parse_torrent_file(sys.argv[4])
            piece_index = int(sys.argv[5])
            save_path = sys.argv[3]
            for ip, port in fetch_peers(torrent_metainfo):
                try:
                    s = get_socket(ip, int(port))
                    peer_handshake(torrent_metainfo, s)
                    piece = download_piece(torrent_metainfo, s, piece_index)
                    with open(save_path, "wb") as f:
                        f.write(piece)
                        return
                except Exception as e:
                    print(e)
        case "download":
            torrent_metainfo = parse_torrent_file(sys.argv[4])
            save_path = sys.argv[3]
            for ip, port in fetch_peers(torrent_metainfo):
                try:
                    s = get_socket(ip, int(port))
                    peer_handshake(torrent_metainfo, s)
                    setup_download(s)
                    file = b""
                    for i in range(len(torrent_metainfo.piece_hashes)):
                        piece = send_download_request(torrent_metainfo, s, i)
                        print(f"Downloaded piece {i}")
                        file += piece
                    with open(save_path, "wb") as f:
                        f.write(file)
                        return
                except Exception as e:
                    print(e)
        case "magnet_parse":
            magnet_link = sys.argv[2]
            query_params = magnet_link[8:].split("&")
            params = dict()
            for p in query_params:
                key, value = p.split("=")
                params[key] = value
            info_hash = params["xt"][9:]
            tracker_url = unquote(params["tr"])
            print(f"Tracker URL: {tracker_url}")
            print(f"Info Hash: {info_hash}")
        case _:
            raise NotImplementedError(f"Unknown command {command}")
if __name__ == "__main__":
    main()