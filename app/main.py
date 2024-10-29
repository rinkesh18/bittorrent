import json
import sys
import bencodepy
from app.download import download_piece
from app.handshake import _handshake
from app.handshake import _handshake, magnet_handshake
from app.magnet import parse_magnet
from app.peers import parse_peers
from app.torrent import decode_torrent, print_torrent_info, parse_hashes
def decode_bencode(bencoded_value):
    bc = bencodepy.Bencode(encoding="utf-8")
    return bc.decode(bencoded_value)
def main():
    command = sys.argv[1]
    if command == "decode":
        bencoded_value = sys.argv[2].encode()
        def bytes_to_str(data):
            if isinstance(data, bytes):
                return data.decode()
        print(json.dumps(decode_bencode(bencoded_value), default=bytes_to_str))
    elif command == "info":
        file_name = sys.argv[2]
        print_torrent_info(file_name)
    elif command == "peers":
        file_name = sys.argv[2]
        t = decode_torrent(file_name)
        ips = parse_peers(t)
        for ip_address, port in ips:
            print(f"{ip_address}:{port}")
    elif command == "handshake":
        file_name = sys.argv[2]
        try:
            peer = sys.argv[3]
        except Exception:
            peer = None
        _handshake(file_name, peer)
    elif command == "download_piece":
        "-o /tmp/test-piece-0 sample.torrent 0"
        flag = sys.argv[2]
        path = sys.argv[3]
        file_name = sys.argv[4]
        piece_index = int(sys.argv[5])
        download_piece(flag, path, file_name, piece_index)
    elif command == "download":
        "download -o /tmp/test.txt sample.torrent"
        flag = sys.argv[2]
        save_path = sys.argv[3]
        file_name = sys.argv[4]
        t = decode_torrent(file_name)
        hashes = parse_hashes(t)
        for piece_index in range(len(hashes)):
            download_piece(flag, save_path, file_name, piece_index)
    elif command == "magnet_parse":
        magnet_link = sys.argv[2]
        print(f"parsing {magnet_link}")
        track_url, info_hash = parse_magnet(magnet_link)
        print(f"Tracker URL: {track_url}")
        print(f"Info Hash: {info_hash}")
    elif command == "magnet_handshake":
        magnet_link = sys.argv[2]
        track_url, info_hash = parse_magnet(magnet_link)
        print(track_url, info_hash)
        magnet_handshake(track_url, info_hash)
if __name__ == "__main__":
    main()