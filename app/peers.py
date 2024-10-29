import bencodepy
import requests
from app.torrent import Torrent
def parse_peers(t: Torrent):
    info_hash = t.info_hash.digest()
    tracker_url = t.tracker_url
    length = t.length
    return request_tracker(tracker_url, info_hash, length)
def request_tracker(tracker_url: str, info_hash: bytes, length: int = 1 << 10):
    params = {
        "info_hash": info_hash,
        "peer_id": "a" * 20,
        "port": 6881,
        "uploaded": 0,
        "downloaded": 0,
        "left": length,
        "compact": 1,
    }
    r = requests.get(tracker_url, params=params)
    bc = bencodepy.Bencode()
    r = bc.decode(r.content)
    print(r)
    byte_seq = r[b"peers"]
    ips = []
    for i in range(0, len(byte_seq), 6):
        ip_bytes = byte_seq[i : i + 4]
        ip_address = ".".join(map(str, list(ip_bytes)))
        port_bytes = byte_seq[i + 4 : i + 6]
        port = port_bytes[0] * 256 + port_bytes[1]
        ips.append((ip_address, port))
    return ips