import json
import socket
import time

import AUtils
import Listener


def agent_main():

    addr = AUtils.get_connection()
    agent_socket = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    agent_socket.connect(addr)
    listener = Listener.ListenerThread(agent_socket)
    listener.start()

    check_time = 0
    while True:
        check_time += 1
        normal_interval, check_interval = AUtils.get_intervals()
        behavior_type = AUtils.get_behavior_type()
        if behavior_type == "proxy" or behavior_type == "error":
            agent_socket.close()
            break

        if behavior_type == "change_server":
            AUtils.set_behavior_type("agent")
            agent_socket.close()
            break

        hardware_info = AUtils.collect_normal()
        saved_status = AUtils.get_hardware()

        if hardware_info != saved_status:
            abnormal_report(agent_socket)

        elif normal_interval > 0 and check_interval == -1:
            normal_report(agent_socket)
            time.sleep(normal_interval)

        elif normal_interval == -1 and check_interval > 0:
            confirmation(agent_socket)
            time.sleep(check_interval)

        else:
            if check_time % check_interval == 0:
                confirmation(agent_socket)
            else:
                normal_report(agent_socket)
            time.sleep(normal_interval)
    listener.join()


def wrap(msg_type, info, rid=-1):
    key = AUtils.get_comm_key()
    timestamp = time.time()
    if rid == -1:
        identity = AUtils.get_identity()
    else:
        identity = rid
    raw_msg = {"type": msg_type, "timestamp": timestamp, "info": info, "identity": identity, "secret": key}

    stamp = AUtils.hash_wrapper(raw_msg)

    raw_msg.pop("secret")
    raw_msg.update({"stamp": stamp})

    return json.dumps(raw_msg)


def normal_report(agent_socket):
    print("normal report...")
    data = wrap("normal", {"report": "none"})
    agent_socket.send(data.encode("utf-8"))


def confirmation(agent_socket):
    # digest saved_status
    print("send confirmation info...")
    info_dict = AUtils.get_hardware()
    info_dict.update({"secret": AUtils.get_comm_key()})
    digest = AUtils.hash_wrapper(info_dict)

    info_dict.pop("secret")
    info_dict.update({"digest": digest})
    data = wrap("confirmation", info_dict)
    info_dict.pop("digest")
    agent_socket.send(data.encode("utf-8"))


def abnormal_report(agent_socket):
    print("send abnormal info...")
    old_status = AUtils.get_hardware()
    new_status = AUtils.collect_normal()
    AUtils.set_hardware(str(new_status))

    abnormal_list = AUtils.find_changes(old_status.copy(), new_status.copy())
    new_status.update({"secret": AUtils.get_comm_key()})
    new_digest = AUtils.hash_wrapper(new_status)
    new_status.pop("secret")

    print("abnormal_report:")
    print(old_status)
    data = wrap("abnormal", {"abnormal_list": abnormal_list, "old_list": old_status, "new_digest": new_digest})

    agent_socket.send(data.encode("utf-8"))

