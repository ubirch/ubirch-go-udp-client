import hashlib
import json
import random
import sys
import time
from binascii import a2b_base64, b2a_base64

import msgpack
import requests

if len(sys.argv) < 3:
    print("usage:")
    print("python3 ./bombard.py <UUID> <AUTH_TOKEN>")
    sys.exit()

number_of_requests_per_type = 50
uuid = sys.argv[1]
auth = sys.argv[2]

data_json_type = "  JSON data"
data_bin_type = "binary data"
hash_bin_type = "binary hash"
hash_b64_type = "base64 hash"

types = [data_json_type, data_bin_type, hash_bin_type, hash_b64_type]

base_url = 'http://localhost:8080'
sign_data_url = base_url + '/{}'.format(uuid)
sign_hash_url = base_url + '/{}/hash'.format(uuid)
vrfy_data_url = base_url + '/verify'
vrfy_hash_url = base_url + '/verify/hash'

auth_header = {'X-Auth-Token': auth}
bin_header = {'Content-Type': 'application/octet-stream'}
txt_header = {'Content-Type': 'text/plain'}
json_header = {'Content-Type': 'application/json'}

symbols = ("a", "b", "c", "d", "e", "f", "A", "B", "C", "D", "E", "F",
           "ä", "ë", "ï", "ö", "ü", "ÿ", "Ä", "Ë", "Ï", "Ö", "Ü", "Ÿ",
           "`", "1", "2", "3", "4", "5", "6", "7", "8", "9", "0", "-", "=",
           "[", "]", ";", "'", "#", ",", ".", "/", "\\",
           "¬", "!", '''"''', "£", "$", "%", "^", "*", "(", ")", "_", "+",
           "{", "}", ":", "@", "~", "?", " |",
           "&", "<", ">", "&#8482",
           "®", "™", "U+2122", "%20", "\\n", "", "\
")
hashes = []  # [(msg, serialized, hash, upp)]
prev_sign = None
max_dur = 0
failed = {}  # init fail counter
for t in types:
    failed[t] = 0


def serialize_msg(msg: dict) -> bytes:
    return json.dumps(msg, separators=(',', ':'), sort_keys=True, ensure_ascii=False).encode()


def hash_bytes(serialized: bytes) -> bytes:
    return hashlib.sha256(serialized).digest()


def to_64(hash_bytes: bytes) -> str:
    return b2a_base64(hash_bytes, newline=False).decode()


# generates a random JSON message
def get_random_json_message() -> dict:
    msg = {
        "id": uuid,
        "ts": int(time.time()),
        "big": random.getrandbits(53),
        "tpl": (random.getrandbits(32), "".join(random.choices(symbols, k=4)),
                random.getrandbits(8), "".join(random.choices(symbols, k=8)),
                random.getrandbits(16), "".join(random.choices(symbols, k=2)),
                random.getrandbits(4), "".join(random.choices(symbols, k=16))
                ),
        "lst": random.choices(symbols, k=8),
        "map": {
            random.choice(symbols): random.getrandbits(4),
            random.choice(symbols): random.getrandbits(16),
            random.choice(symbols): random.getrandbits(8),
            random.choice(symbols): random.getrandbits(32)
        },
        "str": "".join(random.choices(symbols, k=128))
    }
    return msg


def send_request(url: str, headers: dict, data: str or bytes) -> requests.Response:
    global max_dur
    start_time = int(time.time())
    r = requests.post(url=url, headers=headers, data=data)
    dur = int(time.time()) - start_time
    if dur > max_dur: max_dur = dur
    return r


def check_signing_response(r: requests.Response, request_type: str, msg: dict, serialized: bytes, hash_64: str) -> bool:
    try:
        r_map = json.loads(r.text)
    except Exception:
        print("client returned error: ({}) {}\n".format(r.status_code, r.text))
        return False

    if r.status_code != 200:
        print("signing request failed: {} ".format(r.status_code))
        print("requestID: {}\n".format(r_map["requestID"]))
        return False
    else:
        if r_map["hash"] != hash_64:
            print("- - - HASH MISMATCH: {}".format(request_type))
            print("original: {}".format(json.dumps(msg, ensure_ascii=False)))
            print("rendered: {}".format(serialized.decode()))
            print("hash (go): {}".format(r_map["hash"]))
            print("hash (py): {}\n".format(hash_64))

        # check chain
        unpacked = msgpack.unpackb(a2b_base64(r_map["upp"]))
        global prev_sign
        if prev_sign is not None and prev_sign != unpacked[2]:
            print(" - - - PREVIOUS SIGNATURE MISMATCH ! - - - \n")
        prev_sign = unpacked[-1]

    hashes.append((msg, serialized, hash_64, r_map["upp"]))  # [(msg, serialized, hash, upp)]
    return True


def send_signing_request(request_type: str, msg: dict, serialized: bytes, hash_64: str) -> requests.Response:
    if request_type == data_json_type:
        url, header, data = sign_data_url, json_header, json.dumps(msg)
    elif request_type == data_bin_type:
        url, header, data = sign_data_url, bin_header, serialized
    elif request_type == hash_bin_type:
        url, header, data = sign_hash_url, bin_header, a2b_base64(hash_64)
    elif request_type == hash_b64_type:
        url, header, data = sign_hash_url, txt_header, hash_64
    else:
        raise Exception("unknown request type: " + request_type)

    return send_request(url=url, headers={**auth_header, **header}, data=data)


def check_verification_response(r: requests.Response, request_type: str, msg: dict, serialized: bytes, hash_64: str,
                                upp: str) -> bool:
    if r.status_code != 200:
        print(" - - - VERIFICATION FAIL: {}".format(request_type))
        print("original: {}".format(repr(msg)))
        print("rendered: {}".format(serialized.decode()))
        print("hash: {}".format(hash_64))
        print("response: ({}) {}\n".format(r.status_code, r.text))
        return False
    else:
        r_map = json.loads(r.text)

        if upp != r_map["upp"]:
            print(" - - - UPP MISMATCH ! - - - ")
            print("UPP from signing resp.: {}".format(upp))
            print("UPP from verification resp.: {}\n".format(r_map["upp"]))
            return False

    return True


def send_verification_request(request_type: str, msg: dict, serialized: bytes, hash_64: str) -> requests.Response:
    if request_type == data_json_type:
        url, header, data = vrfy_data_url, json_header, json.dumps(msg)
    elif request_type == data_bin_type:
        url, header, data = vrfy_data_url, bin_header, serialized
    elif request_type == hash_bin_type:
        url, header, data = vrfy_hash_url, bin_header, a2b_base64(hash_64)
    elif request_type == hash_b64_type:
        url, header, data = vrfy_hash_url, txt_header, hash_64
    else:
        raise Exception("unknown request type: " + request_type)

    return send_request(url=url, headers=header, data=data)


print("\nsigning {} messages...\n".format(number_of_requests_per_type * len(types)))
for i in range(number_of_requests_per_type):
    for t in types:
        msg = get_random_json_message()
        serialized = serialize_msg(msg)
        hash_64 = to_64(hash_bytes(serialized))
        r = send_signing_request(t, msg, serialized, hash_64)
        if not check_signing_response(r, t, msg, serialized, hash_64):
            failed[t] += 1

    if (i + 1) % 10 == 0 and i != 0:
        for t in types:
            print("{:3} of {} {} signing requests failed.".format(failed[t], (i + 1), t))
        print()

print(" max. signing duration: {} sec\n".format(max_dur))

max_dur = 0  # reset timer
for t in types:  # reset fail counter
    failed[t] = 0

print("verifying {} hashes...\n".format(len(hashes)))
for i, (msg, serialized, hash_64, upp) in enumerate(hashes):

    for t in types:
        r = send_verification_request(t, msg, serialized, hash_64)
        if not check_verification_response(r, t, msg, serialized, hash_64, upp):
            failed[t] += 1

    if (i + 1) % 10 == 0:
        for t in types:
            print("{:3} of {} {} verification requests failed.".format(failed[t], (i + 1), t))
        print()

print(" max. verification duration: {} sec\n".format(max_dur))
