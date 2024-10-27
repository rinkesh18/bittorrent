import json
import sys


def decode_bencode(bencoded_value):
    # Decode a bencoded value (string or integer)
    if chr(bencoded_value[0]).isdigit():  # Check if it starts with a digit (string)
        first_colon_index = bencoded_value.find(b":")
        if first_colon_index == -1:
            raise ValueError("Invalid encoded value")

        length = int(bencoded_value[:first_colon_index])
        start = first_colon_index + 1
        end = start + length

        if end > len(bencoded_value):
            raise ValueError("Invalid encoded value")

        return bencoded_value[start:end]

    elif chr(bencoded_value[0]) == "i" and chr(bencoded_value[-1]) == "e":  # Check for integer
        return int(bencoded_value[1:-1])

    else:
        raise NotImplementedError('Only strings and integers are supported at the moment')


def main():
    command = sys.argv[1]

    if command == "decode":
        bencoded_value = sys.argv[2].encode()

        def bytes_to_str(data):
            if isinstance(data, bytes):
                return data.decode()
            raise TypeError(f"Type not serializable: {type(data)}")

        print(json.dumps(decode_bencode(bencoded_value), default=bytes_to_str))
    else:
        raise NotImplementedError(f"Unknown command {command}")


if __name__ == "__main__":
    main()