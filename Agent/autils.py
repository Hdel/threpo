import time

import random

import json
import os
from configparser import ConfigParser
import hashlib

config_file = os.path.dirname(__file__) + "/agent.conf"
hw_file_name = os.path.dirname(__file__) + "/hardware"


def get_behavior_type():
    # get it from conf_file
    config = ConfigParser()
    config.read(config_file)
    behavior_type = config.get("whoami", "role")
    return behavior_type


def set_behavior_type(b_type):
    config = ConfigParser()
    config.read(config_file)

    config.set("whoami", "role", b_type)
    with open(config_file, 'w') as f:
        config.write(f)


def set_interval(which, value):
    config = ConfigParser()
    config.read(config_file)

    config.set("interval", which, str(value))
    with open(config_file, 'w') as f:
        config.write(f)


def set_server_proxy(addr=0):
    config = ConfigParser()
    config.read(config_file)

    if type(addr) == int:
        addr = config.get("connection", "server_host")

    config.set("connection", "host", addr)
    with open(config_file, 'w') as f:
        config.write(f)


def set_key_proxy(key=0):
    config = ConfigParser()
    config.read(config_file)

    if type(key) == int:
        key = config.get("whoami", "key")

    config.set("whoami", "key", key)
    with open(config_file, 'w') as f:
        config.write(f)


def get_intervals():
    # get it from conf_file
    config = ConfigParser()
    config.read(config_file)
    normal_interval = float(config.get("interval", "normal_interval"))
    check_interval = int(config.get("interval", "check_interval"))
    return normal_interval, check_interval


def get_comm_key():
    # get it from conf_file
    config = ConfigParser()
    config.read(config_file)
    comm_key = config.get("whoami", "key")
    return comm_key


def get_identity():
    # get it from conf file
    config = ConfigParser()
    config.read(config_file)
    comm_identity = config.get("whoami", "identity")

    return int(comm_identity)


# helps to wrap a message
# message may not be str(since I kept making mistakes)
def hash_wrapper(msg):
    hash_obj = hashlib.sha256()
    hash_obj.update(str(msg).encode('utf-8'))
    return hash_obj.hexdigest()


# set file "hardware"
# whenever changes occur

def set_hardware(hardware_dict):
    global hw_file_name
    with open(hw_file_name, "w") as w_file:
        info_string = str(hardware_dict)
        w_file.write(info_string)


def get_hardware():
    global hw_file_name
    try:
        hw_file = open(hw_file_name, "r")
        hw_string = hw_file.read()
        if hw_string == '':
            with open(hw_file_name, "w") as w_file:
                hw_dict = collect_normal()
                info_string = str(hw_dict)
                w_file.write(info_string)

        else:
            hw_string = hw_string.replace('\'', '\"')
            hw_dict = json.loads(hw_string)

    finally:
        if hw_file:
            hw_file.close()
    print(hw_dict)
    return hw_dict


def get_intervals():
    config = ConfigParser()
    config.read(config_file)
    return float(config.get("interval", "normal_interval")), int(config.get("interval", "check_interval"))


def collect_normal():
    if os.name == "posix":
        import lutils
        return lutils.collect_normal()

    elif os.name == "nt":
        import wutils
        return wutils.CollectInfo().collect_normal()

    else:
        return {"error": "os not recognized"}


def get_connection():
    # get it from conf file
    config = ConfigParser()
    config.read(config_file)
    host = config.get("connection", "host")
    port = int(config.get("connection", "port"))
    return (host, port)


def wrap_reg(info):
    key_alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890"
    key_space = len(key_alphabet)
    random.seed(time.time())
    key = ""

    # generate a ramdom key
    for i in range(32):
        key += key_alphabet[random.randint(0, key_space-1)]

    info.update({"secret": key})
    return json.dumps({"type": "registration", "info": info}), key


def find_changes(old_status, new_status):
    abnormal_list = []
    for label in old_status:
        # no difference
        if old_status[label] == new_status[label]:
            continue
        else:
            old_list = old_status[label].copy()
            new_list = new_status[label].copy()

            for item in old_list:
                if item in new_list:
                    new_list.remove(item)
                else:
                    # type 2: removal
                    # this event entry means:
                    # item(type: label) is removed
                    abnormal_event = {"res_type": label, "abnormal_type": 2, "description": item}
                    abnormal_list.append(abnormal_event)

            # all the items left in new_list are items not in old_list
            # in other words, NEW ITEMS
            for item in new_list:
                abnormal_event = {"res_type": label, "abnormal_type": 3, "description": item}
                abnormal_list.append(abnormal_event)

    return abnormal_list

