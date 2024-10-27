import json
import sys
import bencode

def decode_bencode(bencoded_value):
    if bencoded_value.startswith(b'i') and bencoded_value.endswith(b'e'):
        # Decode integer
        try:
            return int(bencoded_value[1:-1])
        except ValueError:
            raise ValueError("Invalid integer format")

    elif bencoded_value[0:1].isdigit():  # Check if it starts with a digit (string)
        first_colon_index = bencoded_value.find(b":")
        if first_colon_index == -1:
            raise ValueError("Invalid encoded value")

        length = int(bencoded_value[:first_colon_index])
        start = first_colon_index + 1
        end = start + length

        if end > len(bencoded_value):
            raise ValueError("Invalid encoded value")

        return bencoded_value[start:end]

    elif bencoded_value.startswith(b'l') and bencoded_value.endswith(b'e'):
        # Decode list
        items = []
        current_index = 1  # Start after 'l'

        while current_index < len(bencoded_value) - 1:  # Until 'e'
            if bencoded_value[current_index:current_index + 1] == b'i':
                # It's an integer
                end_index = bencoded_value.find(b'e', current_index)
                if end_index == -1:
                    raise ValueError("Invalid encoded list")
                items.append(int(bencoded_value[current_index + 1:end_index]))
                current_index = end_index + 1
            elif bencoded_value[current_index:current_index + 1].isdigit():
                # It's a string
                first_colon_index = bencoded_value.find(b":", current_index)
                if first_colon_index == -1:
                    raise ValueError("Invalid encoded list")

                length = int(bencoded_value[current_index:first_colon_index])
                start = first_colon_index + 1
                end = start + length

                if end > len(bencoded_value):
                    raise ValueError("Invalid encoded list")

                items.append(bencoded_value[start:end])
                current_index = end
            else:
                raise NotImplementedError('Only strings and integers are supported at the moment')

        return items

    # else:
    #     raise NotImplementedError('Only strings and integers are supported at the moment')


def main():
    command = sys.argv[1]

    if command == "decode":
        bencoded_value = sys.argv[2].encode()

        def bytes_to_str(data):
            if isinstance(data, bytes):
                return data.decode()
            raise TypeError(f"Type not serializable: {type(data)}")

        try:
            decoded_value = decode_bencode(bencoded_value)
            print(json.dumps(decoded_value, default=bytes_to_str))
        except Exception as e:
            print(f"Error: {e}")
            sys.exit(1)
    else:
        raise NotImplementedError(f"Unknown command {command}")


if __name__ == "__main__":
    main()