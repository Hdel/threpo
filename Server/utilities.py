import random
import time
import json
import hashlib

import pymysql

import DatabaseUtils

server_addr = '127.0.0.1'
server_port = 9556


# sample output:
# not yet well tested on virtual machine

# on win32 env
# cpu_info : [{'name': 'Intel(R) Core(TM) i5-8300H CPU @ 2.30GHz', 'core': 4}]
# ram_info : [{'size': 4096, 'manufacturer': '802C0000802C', 'sn': '1CA46C30'}, {'size': 4096, 'manufacturer': '802C0000802C', 'sn': '1CA46B6F'}]
# disk_info : [{'name': 'KXG50ZNV256G NVMe TOSHIBA 256GB', 'sn': '0000_0000_0000_0010_0008_0D03_0038_74EB.', 'size': 238}]
# nic_info : ['9C:B6:D0:B8:42:E3']
# gcard_info : ['Intel(R) UHD Graphics 630']

# on ubuntu(virtual box) env
# cpu_info: [{'name': 'Intel(R) Core(TM) i5-8300H CPU @ 2.30GHz', 'core': 1}]
# ram_info: [{'size': 1993, 'manufacturer': 'not retrieved', 'sn': 'not retrieved'}]
# disk_info: [{'name': 'VBOX HARDDISK', 'sn': 'VBaec0675e-06b568b', 'size': 20}]
# nic_info: ['08:00:27:f2:3f:3b']
# gcard_info: ['VMware SVGA II Adapter']


def random_gen():
    key_alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890"
    key_space = len(key_alphabet)
    random.seed(time.time())
    key = ""

    # generate a ramdom key
    for i in range(32):
        key += key_alphabet[random.randint(0, key_space-1)]
    return key


def get_valid_interval(msg_type):
    return 10


def check_integrity(msg, key=0):
    info_dict = eval(str(msg))

    if type(key) == int:
        cur_key = get_key_by_id(info_dict["identity"])
    else:
        cur_key = key

    print(key)

    stamp = info_dict["stamp"]
    msg_time = info_dict["timestamp"]
    msg_type = info_dict["type"]
    identity = info_dict["identity"]

    valid_interval = get_valid_interval(msg_type)

    info_dict.pop("stamp")
    info_dict.update({"secret": cur_key})

    print(info_dict)

    hex_digest = hash_wrapper(info_dict)

    if hex_digest == stamp:
        if time.time() - msg_time <= valid_interval:
            return {"type": msg_type, "identity": identity, "status": "sound", "info": info_dict["info"]}
        return {"status": "error", "description": "time out"}
    else:
        print(hash(json.dumps(info_dict)))
        return {"status": "error", "description": "integrity check failed"}


def unwrap(msg, key):
    check_result = check_integrity(msg, key)
    return check_result


def hash_wrapper(msg):
    hash_obj = hashlib.sha256()
    hash_obj.update(str(msg).encode('utf-8'))
    return hash_obj.hexdigest()


def get_key_by_id(conn: pymysql.Connection, identity: int):
    cursor = conn.cursor()
    cursor.execute("select secret from machines where id=%d" % identity)
    query_result = cursor.fetchone()
    if query_result is None:
        return None
    else:
        return query_result[0]


def check_digest(conn: pymysql.Connection, identity: int, info: dict, sent_digest: str):
    cursor = conn.cursor()
    cursor.execute("select secret, digest from machines where id=%d" % identity)
    result = cursor.fetchone()
    secret, digest = result[0], result[1]

    dict_with_secret = info.update({"secret": secret})
    calculated_hash = hash_wrapper(dict_with_secret)

    if not len(set([digest, calculated_hash, sent_digest])) == 1:
        return {"status": "error", "description": "digest check failed"}

    else:
        return {"status": "sound"}


def get_distance(ip1, ip2):
    ip_list_1 = ip1.split('.')
    result_1 = 0
    for i in range(4):
        result_1 = result_1 + int(ip_list_1[i]) * 256 ** (3 - i)

    ip_list_2 = ip2.split('.')
    result_2 = 0
    for i in range(4):
        result_2 = result_2 + int(ip_list_2[i]) * 256 ** (3 - i)

    return abs(result_2-result_1)
