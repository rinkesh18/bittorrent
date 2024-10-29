import json
import sys
import hashlib
import bencodepy
import requests
import socket
import concurrent.futures
import queue
from urllib.parse import unquote

# Global queues for managing pieces and peers
pending_pieces = queue.Queue()
free_peers = queue.Queue()

def decode_bencode(bencoded_value):
    if len(bencoded_value) < 1:
        return None, bencoded_value

    if bencoded_value[0].isdigit():
        first_colon_index = bencoded_value.find(b":")
        size = int(bencoded_value[:first_colon_index])
        item = bencoded_value[first_colon_index + 1: first_colon_index + size + 1]
        return item, bencoded_value[first_colon_index + size + 1:]

    elif bencoded_value[0] == ord('i'):
        first_e_index = bencoded_value.find(b"e")
        item = int(bencoded_value[1:first_e_index])
        return item, bencoded_value[first_e_index + 1:]

    elif bencoded_value[0] == ord('l'):
        bencoded_value = bencoded_value[1:]
        items = []
        while True:
            item, bencoded_value = decode_bencode(bencoded_value)
            if item is None:
                break
            items.append(item)
        return items, bencoded_value[1:]

    elif bencoded_value[0] == ord('d'):
        bencoded_value = bencoded_value[1:]
        items = {}
        while True:
            key, bencoded_value = decode_bencode(bencoded_value)
            if key is None:
                break
            value, bencoded_value = decode_bencode(bencoded_value)
            items[key.decode()] = value
        return items, bencoded_value[1:]

    raise NotImplementedError("Unsupported bencoded type")

def info(file):
    with open(file, "rb") as f:
        benc = f.read()
    data, _ = decode_bencode(benc)
    encoded_info = bencodepy.encode(data["info"])
    info_hash = hashlib.sha1(encoded_info).digest()
    return info_hash, data

def peers(digest, data):
    payload = {
        "info_hash": digest,
        "peer_id": "99887766554433221100",
        "port": 6881,
        "uploaded": 0,
        "downloaded": 0,
        "left": data["info"]["length"],
        "compact": 1,
    }
    response = requests.get(data["announce"], params=payload)
    response_data = bencodepy.decode(response.content)
    peers_list = []

    for i in range(0, len(response_data[b"peers"]), 6):
        peer_ip = response_data[b"peers"][i:i + 4]
        peer_port = response_data[b"peers"][i + 4:i + 6]
        peers_list.append(
            (
                ".".join([str(peer_ip[j]) for j in range(4)]),
                peer_port[0] * 256 + peer_port[1],
            )
        )
    return peers_list

def handshake(digest, ip, port):
    packet = b"\x13BitTorrent protocol\x00\x00\x00\x00\x00\x00\x00\x00" + digest + b"00112233445566778899"
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((ip, port))
        s.sendall(packet)
        response = s.recv(68)
        peer_id = response[48:]
        ext_support = response[25] == 0x10
        print("Peer ID:", peer_id.hex())  # Ensure the Peer ID is printed
        return peer_id.hex(), ext_support

def main():
    command = sys.argv[1]
    if command == "handshake":
        ip, port = sys.argv[3].split(":")
        digest, data = info(sys.argv[2].encode())
        peer_id, ext_support = handshake(digest, ip, int(port))
        # print("Peer ID:", peer_id)  # Print the peer ID after handshake

if __name__ == "__main__":
    main()