import re
import urllib.parse
def parse_magnet(magnet_link: str):
    # info_hash = re.findall(r"xt=urn:btih:([a-fA-F0-9]{40})", magnet_link)
    info_hash = re.findall(r"xt=urn:btih:(.{40})", magnet_link)[0]
    # download_name = re.findall(r"dn=(.*?)&", magnet_link)[0]
    track_url = urllib.parse.unquote(re.findall(r"tr=(.*)", magnet_link)[0])
    # print(info_hash, download_name, track_url)
    return track_url, info_hash
if __name__ == "__main__":
    magnet_link = "magnet:?xt=urn:btih:ad42ce8109f54c99613ce38f9b4d87e70f24a165&dn=magnet1.gif&tr=http%3A%2F%2Fbittorrent-test-tracker.codecrafters.io%2Fannounce"
    parse_magnet(magnet_link)