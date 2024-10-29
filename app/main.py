import json
import sys
import bencodepy
# import bencodepy - available if you need it!
# import requests - available if you need it!
bc = bencodepy.Bencode(encoding="utf-8")
# Examples:
#
# - decode_bencode(b"5:hello") -> b"hello"
# - decode_bencode(b"10:hello12345") -> b"hello12345"
def decode_bencode(bencoded_value):
    # return bencodepy.decode(bencoded_value)
    return bc.decode(bencoded_value)
def main():
    command = sys.argv[1]
    if command == "decode":
        bencoded_value = sys.argv[2].encode()
        # json.dumps() can't handle bytes, but bencoded "strings" need to be
        # bytestrings since they might contain non utf-8 characters.
        #
        # Let's convert them to strings for printing to the console.
        def bytes_to_str(data):
            if isinstance(data, bytes):
                return data.decode()
            raise TypeError(f"Type not serializable: {type(data)}")
        print(json.dumps(decode_bencode(bencoded_value), default=bytes_to_str))
    elif command == "info":
        file_name = sys.argv[2]
        with open(file_name, "rb") as torrent_file:
            bencoded_content = torrent_file.read()
        torrent = decode_bencode(bencoded_content)
        print("Tracker URL:", torrent["announce"].decode())
        print("Length:", torrent["info"]["length"])
    else:
        raise NotImplementedError(f"Unknown command {command}")
if __name__ == "__main__":
    main()