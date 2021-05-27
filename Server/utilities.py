import time
import json
import hashlib
import database_ops


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


def get_valid_interval(msg_type):
    return 10


def check_integrity(msg, key):
    info_dict = json.loads(msg)

    if info_dict["type"] == "registration":
        return {"type": "registration", "info": info_dict["info"], "status": "sound"}

    if type(key) == int:
        cur_key = database_ops.Actions().get_comm_key(info_dict["identity"])
    else:
        cur_key = key
    stamp = info_dict["stamp"]
    msg_time = info_dict["timestamp"]
    msg_type = info_dict["type"]
    identity = info_dict["identity"]
    valid_interval = get_valid_interval(msg_type)

    info_dict.pop("stamp")
    info_dict.update({"key": cur_key})

    sha256_hash = hashlib.sha256()
    sha256_hash.update(str(info_dict).encode("utf-8"))

    if sha256_hash.hexdigest() == stamp:
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



