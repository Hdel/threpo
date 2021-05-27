import json
import os
from configparser import ConfigParser
import hashlib

config_file = "agent.conf"


# helps to wrap a message
# message may not be str(since I kept making mistakes)
def hash_wrapper(msg):
    hash_obj = hashlib.sha256()
    hash_obj.update(str(msg).encode('utf-8'))
    return hash_obj.hexdigest()


# set file "hardware"
# whenever changes occure
def set_hardware(hardware_dict):
    with open("hardware", "w") as w_file:
        info_string = str(hardware_dict)
        w_file.write(info_string)


def get_hardware():
    try:
        hw_file = open("hardware", "r")
        hw_string = hw_file.read()
        if hw_string == '':
            with open("hardware", "w") as w_file:
                hw_dict = collect_normal()
                info_string = str(hw_dict)
                w_file.write(info_string)

        else:
            hw_string = hw_string.replace('\'', '\"')
            hw_dict = json.loads(hw_string)

    finally:
        if hw_file:
            hw_file.close()

    return hw_dict


def get_intervals():
    config = ConfigParser()
    config.read(config_file)
    return float(config.get("interval", "normal_report")), int(config.get("interval", "check_report"))


def collect_normal():
    if os.name == "posix":
        import lutils
        return lutils.collect_normal()

    elif os.name == "nt":
        import wutils
        return wutils.Win32Info().collect_normal()

    else:
        return {"error": "os not recognized"}


def get_connection():
    # get it from conf file
    config = ConfigParser()
    config.read(config_file)
    host = config.get("connection", "host")
    port = int(config.get("connection", "port"))
    return host, port
