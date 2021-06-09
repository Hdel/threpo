import hashlib
import os
import sqlite3
import time
import json
import socket
import ssl
import random
import threading
from configparser import ConfigParser

import autils
import lutils
import utilities
from autils import get_intervals, collect_normal, get_hardware, get_connection, hash_wrapper

# global var section 1
# connection information
server_addr = '127.0.0.1'
server_port = 9556

# section 2
# config file information
config_file = "agent.conf"

# section 3
# hardware information
saved_status = {}
saved_digest = ""

# section 4
# communication information
comm_key = ""
comm_identity = -1

# section 5
# time intervals
interval_normal = -1
interval_confirm = -1

behavior_type = "agent"
cancel = 0
message_pool = []


def config_refresh():
    global server_addr, server_port, comm_key, comm_identity, interval_normal, interval_confirm
    config = ConfigParser()
    config.read(config_file)
    interval_normal = int(config.get("interval", "normal_interval"))
    interval_confirm = int(config.get("interval", "check_interval"))

    server_addr = config.get("connection", "host")
    server_port = int(config.get("connection", "port"))
    comm_key = config.get("whoami", "key")
    comm_identity = config.get("whoami", "identity")


def config_refresh_proxy(proxy_addr, proxy_port, proxy_comm_key):
    global server_addr, server_port, comm_key

    if proxy_addr == "0":
        config_refresh()
    else:
        server_addr = proxy_addr
        server_port = proxy_port
        comm_key = proxy_comm_key


class ProxyAgentHandler(threading.Thread):
    key_settled = False
    thread_key = 0

    # save ssl_socket information
    def __init__(self, client_sock, addr):
        threading.Thread.__init__(self)
        self.client_socket = client_sock
        self.client_addr = addr
        self.conn = sqlite3.connect('db.sqlite3')

    def run(self):
        global cancel
        print("start thread")
        while True:
            msg = self.client_socket.recv(4096).decode("utf-8")
            if not msg:
                break
            if cancel < 0:
                ret_dict = dict()
                ret_dict["type"] == "change_server"
                ret_dict["new_addr"] = "0"
                ret_dict["new_port"] = "0"
                ret_dict["new_key"] = "0"
                self.client_socket.send(str(ret_dict).encode("utf-8"))
                cancel += 1
                break
            # unwrap the message
            # format:
            # "type": str, "identity": int, "status": str, "info":dict
            result = utilities.unwrap(msg, self.thread_key)
            if result["status"] == "sound":
                print(f"receive msg from client {self.client_addr}：{msg}")
                if result["type"] == "registration":
                    new_msg = "2"
                    cursor = self.conn.cursor()
                    cursor.execute("select id from agent where key='%s'" % result["info"]["secret"])

                    self.thread_key = result["info"]["secret"]
                    self.key_settled = 1
                    self.client_socket.send(new_msg.encode("utf-8"))
                    continue
                else:
                    new_msg = str(self.parse(result, msg))
                    self.client_socket.send(new_msg.encode("utf-8"))
            else:
                print(result["status"] + ': ' + result["description"])
                self.client_socket.send(str(1).encode("utf-8"))

    def parse(self, result, msg):
        # redirect to different functions
        method_dict = {
            "normal": proxy_normal,
            "confirmation": proxy_normal,
            "abnormal": proxy_abnormal,
        }
        # print(result)
        msg_type = result["type"]
        return method_dict.get(msg_type)(result, msg)

    # when thread is destroyed
    # close the ssl_socket
    def __del__(self):
        print("thread del called here")
        self.client_socket.close()


def proxy_normal(result, msg):
    global message_pool
    try:
        conn = sqlite3.connect('db.sqlite3')
        cursor = conn.cursor()
        cursor.execute("update agent set op_timestamp=%f where id=%d" % (time.time(), result["identity"]))
        conn.commit()
        conn.close()
    except IndexError:
        message_pool.append(msg)
    return 1


def proxy_abnormal(result, msg):
    abnormal_list = result["info"]["abnormal_list"]
    old_list = result["info"]["old_list"].copy()
    identity = result["identity"]
    del_list = []
    insert_list = []

    conn = sqlite3.connect('db.sqlite3')
    cursor = conn.cursor()
    cursor.execute("select secret, digest from agent where id=%d" % result["identity"])
    fetched = cursor.fetchone()
    key, digest = fetched[0], fetched[1]

    old_list.update({"secret": key})
    calculated_hash = hash_wrapper(old_list)
    old_list.pop("secret")

    if calculated_hash == digest:
        for entry in abnormal_list:
            # if this resource is deleted
            if entry["abnormal_type"] == 3:
                insert_list.append({"res_type": entry["res_type"], "content": entry["description"]})
                old_list[entry["res_type"]].append(entry["description"])
            # if a new resource added
            elif entry["abnormal_type"] == 2:
                del_list.append({"res_type": entry["res_type"], "content": entry["description"]})
                old_list[entry["res_type"]].remove(entry["description"])

        # check if changes provided matches with new hash digest
        new_digest = result["info"]["new_digest"]
        for entry in old_list:
            old_list[entry].sort(key=str)

        old_list.update({"secret": key})
        calculated_digest = hash_wrapper(old_list)
        old_list.pop("secret")

        if new_digest == calculated_digest:
            wrap("change_checked", {"abnormal_list": abnormal_list}, identity)
            message_pool.append()
            return "0"

    message_pool.append(msg)
    return "1"


class ServerSSL:
    def __init__(self):
        self.thread_list = []

    def build_listen(self):
        global cancel
        context = ssl.SSLContext(ssl.PROTOCOL_TLSv1)
        context.load_cert_chain(certfile="cert.pem", keyfile="key.pem")

        # listen
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0) as sock:
            sock.bind(('127.0.0.1', 9556))
            sock.listen(5)
            with context.wrap_socket(sock, server_side=True) as ssock:
                while True:
                    # accept the client
                    client_socket, addr = ssock.accept()
                    # start a new thread to handle it
                    thread = ProxyAgentHandler(client_socket, addr)
                    self.thread_list.append((thread, addr))
                    thread.start()
                    cancel += 1


class ProxyThreadServer(threading.Thread):
    def __init__(self, ssl_sock):
        threading.Thread.__init__(self)
        self.ssl_sock = ssl_sock

    def run(self):
        global behavior_type
        while True:
            if len(message_pool) != 0:
                messages = message_pool.copy()
                message_pool.clear()
                for message in messages:
                    self.ssl_sock.send(message.encode("utf-8"))

            hardware_info = collect_normal()
            if hardware_info == saved_status:
                ret_pro = str(self.ssl_sock.normal_report())
                time.sleep(max(interval_normal, interval_confirm))
            else:
                ret_pro = str(self.ssl_sock.abnormal_report())

            time.sleep(1)

            if ret_pro == "cancel":
                global cancel
                behavior_type = "agent"
                cancel = -cancel
                time.sleep(10)
                break


class ProxyThread(threading.Thread):
    def __init__(self, ssl_sock):
        threading.Thread.__init__(self)
        self.ssl_sock = ssl_sock
        self.primitive_addr = []
        self.agent_list = []
        self.conn = sqlite3.connect('db.sqlite3')
        cursor = self.conn.cursor()
        cursor.execute('create table agent(id, secret char(32), digest char(64), op_timestamp decimal(10, 0))')
        self.conn.commit()

    def run(self):
        data = wrap("proxy_reg", {"registration": "True"})
        self.ssl_sock.send(data.encode("utf-8"))

        while True:
            reply = str(self.ssl_sock.recv(1024).decode())
            if reply == "done":
                break
            else:
                self.primitive_addr.append(reply)

        for addr in self.primitive_addr:
            rtt = lutils.ping_rtt(addr)
            data = {"type": "proxy", "addr": addr, "rtt": rtt}
            self.ssl_sock.send(data.encode("utf-8"))

        while True:
            reply = str(self.ssl_sock.recv(1024).decode())
            if reply == "done":
                break
            else:
                reply = eval(reply)
                cursor = self.conn.cursor()
                cursor.execute("insert into agent (id, secret, digest, op_timestamp) values(%d, '%s', '%s', %f)" %
                               (reply["identity"], reply["secret"], reply["digest"], time.time()))

        to_server_thread = ProxyThreadServer(self.ssl_sock)
        to_server_thread.start()

        ssl_proxy = ServerSSL()
        ssl_proxy.build_listen()
        to_server_thread.join()

    def __del__(self):
        self.ssl_sock.close()
        global behavior_type
        behavior_type= "agent"
        self.conn.close()
        os.unlink("db.sqlite3")


class SenderThread(threading.Thread):
    def __init__(self, ssl_sock):
        threading.Thread.__init__(self)
        self.ssl_sock = ssl_sock

    def run(self):
        global behavior_type
        print("thread start...")
        if interval_normal > 0 and interval_confirm == -1:
            while True:
                hardware_info = collect_normal()
                if hardware_info == saved_status:
                    ret_pro = self.ssl_sock.normal_report()
                    time.sleep(interval_normal)
                else:
                    ret_pro = self.ssl_sock.abnormal_report()
                if len(ret_pro) > 2:
                    ret_dict = eval(ret_pro)
                    if ret_dict["type"] == "proxy":
                        behavior_type = "proxy"
                        break
                    elif ret_dict["type"] == "change_server":
                        new_addr = ret_dict["new_addr"]
                        new_port = ret_dict["new_port"]
                        new_key = ret_dict["new_key"]
                        config_refresh_proxy(new_addr, new_port, new_key)
                        break
                    elif ret_dict["type"] == "change_config":
                        config = ConfigParser()
                        config.read(config_file)
                        for info in ret_dict["info"]:
                            config.set(info["section"], info["config"], info["value"])
                        config.write(open("agent.conf", "w"))
                        config_refresh()

        elif interval_normal == -1 and interval_confirm > 0:
            while True:
                hardware_info = collect_normal()
                if hardware_info == saved_status:
                    ret_pro = self.ssl_sock.confirm_report()
                    time.sleep(interval_normal)
                else:
                    ret_pro = self.ssl_sock.abnormal_report()
                if len(ret_pro) > 2:
                    ret_dict = eval(ret_pro)
                    if ret_dict["type"] == "proxy":
                        behavior_type = "proxy"
                        break
                    elif ret_dict["type"] == "change_server":
                        new_addr = ret_dict["new_addr"]
                        new_port = ret_dict["new_port"]
                        new_key = ret_dict["new_key"]
                        config_refresh_proxy(new_addr, new_port, new_key)
                        break
                    elif ret_dict["type"] == "change_config":
                        config = ConfigParser()
                        config.read(config_file)
                        for info in ret_dict["info"]:
                            config.set(info["section"], info["config"], info["value"])
                        config.write(open("agent.conf", "w"))
                        config_refresh()

        else:
            check_time = 1
            while True:
                hardware_info = collect_normal()
                # send a verbose report
                check_time += 1
                if check_time % interval_confirm == 0:
                    if hardware_info == saved_status:
                        ret_pro = self.ssl_sock.confirmation()
                        time.sleep(interval_normal)
                    else:
                        ret_pro = self.ssl_sock.abnormal_report()

                # send a short report
                else:
                    if hash_wrapper(hardware_info) == saved_digest:
                        ret_pro = self.ssl_sock.normal_report()
                        time.sleep(interval_normal)
                    else:
                        ret_pro = self.ssl_sock.abnormal_report()
                if len(ret_pro) > 2:
                    ret_dict = eval(ret_pro)
                    if ret_dict["type"] == "proxy":
                        behavior_type = "proxy"
                        break
                    elif ret_dict["type"] == "change_server":
                        new_addr = ret_dict["new_addr"]
                        new_port = ret_dict["new_port"]
                        new_key = ret_dict["new_key"]
                        config_refresh_proxy(new_addr, new_port, new_key)
                        break
                    elif ret_dict["type"] == "change_config":
                        config = ConfigParser()
                        config.read(config_file)
                        for info in ret_dict["info"]:
                            config.set(info["section"], info["config"], info["value"])
                        config.write(open("agent.conf", "w"))
                        config_refresh()

    def __del__(self):
        print("thread del called here")
        self.ssl_sock.close()


# this function helps to find difference between two hardware lists
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


def get_saved_status():
    if saved_status == {}:
        return get_hardware()
    else:
        return saved_status.copy()


def get_identity():
    global comm_identity

    # if the identity is not initialized
    if comm_identity == -1:
        # get it from conf file
        config = ConfigParser()
        config.read(config_file)
        comm_identity = config.get("whoami", "identity")

    return int(comm_identity)


def get_comm_key():
    global comm_key

    # if the communication key is not initialized
    if comm_key == "":
        # get it from conf_file
        config = ConfigParser()
        config.read(config_file)
        comm_key = config.get("whoami", "key")
    return comm_key


# python 3.6 dict is ordered
# no other pre-process needed
def wrap(msg_type, info, rid=-1):
    key = get_comm_key()
    timestamp = time.time()
    if rid == -1:
        identity = get_identity()
    else:
        identity = rid
    raw_msg = {"type": msg_type, "timestamp": timestamp, "info": info, "identity": identity, "key": key}

    sha256_hash = hashlib.sha256()
    sha256_hash.update(str(raw_msg).encode("utf-8"))

    stamp = sha256_hash.hexdigest()
    raw_msg.pop("key")
    raw_msg.update({"stamp": stamp})

    return json.dumps(raw_msg)


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


class ClientSSL:
    def __init__(self, ):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.ssl_sock = ssl.wrap_socket(s, ca_certs="cert/cert.pem", cert_reqs=ssl.CERT_REQUIRED)
        self.ssl_sock.connect((server_addr, server_port))

    def __del__(self):
        self.ssl_sock.close()

    def send_hello(self):
        # used test connection
        self.ssl_sock.send("connected to the server?".encode("utf-8"))
        print(type(self.ssl_sock.recv(1024).decode()))

    def send_data(self, msg_type, msg):
        # wrap data: add digest, timestamp etc.
        data = wrap(msg_type, msg)

        self.ssl_sock.send(data.encode("utf-8"))
        print(type(self.ssl_sock.recv(1024).decode()))

    def registration(self):
        # open config_file to check if the agent is already registered
        print("registration...")
        config = ConfigParser()
        config.read(config_file)
        identity = int(config.get("whoami", "identity"))

        # if not registered, the identity of the agent is by default -1
        if int(identity) == -1:
            # collect basic information of the agent
            info = collect_normal()
            # store a copy of initial status of resources
            saved_status.update(info)
            # data: to be sent to the server
            # key: used later
            data, key = wrap_reg(info)

            # send registration information the server
            self.ssl_sock.send(data.encode("utf-8"))
            reg_result = int(self.ssl_sock.recv(1024))

            # for some reason, registration failed
            if reg_result == -1:
                return 1
            # registration succeed
            else:
                # write changes into conf file
                config.set("whoami", "identity", str(reg_result))
                config.set("whoami", "key", key)
                config.write(open("agent.conf", "w"))
                return 0

        else:
            # already registered before.
            # conf file already written
            # at this time query stored resource information from the server
            print(get_hardware())
            print(collect_normal())
            abnormal_list = find_changes(get_hardware(), collect_normal())
            if len(abnormal_list) == 0:
                return 2
            else:
                return self.abnormal_report()

    def normal_report(self):
        print("normal report...")
        data = wrap("normal", {"report": "none"})
        self.ssl_sock.send(data.encode("utf-8"))
        reply = self.ssl_sock.recv(1024)
        print(reply.decode())
        return str(reply.decode())

    def confirmation(self):
        # digest saved_status
        print("send confirmation info...")
        info_dict = saved_status
        info_dict.update({"secret": get_comm_key()})
        hash_obj = hashlib.sha256()
        hash_obj.update(str(info_dict).encode("utf-8"))
        digest = hash_obj.hexdigest()

        info_dict.pop("secret")
        info_dict.update({"digest": digest})
        data = wrap("confirmation", info_dict)
        info_dict.pop("digest")
        self.ssl_sock.send(data.encode("utf-8"))
        reply = self.ssl_sock.recv(1024)
        print(reply.decode())
        return str(reply.decode())

    def abnormal_report(self):
        global saved_status
        print("send abnormal info...")
        old_status = get_saved_status()

        while True:
            new_status = collect_normal()

            abnormal_list = find_changes(old_status.copy(), new_status.copy())
            new_status.update({"secret": get_comm_key()})
            new_digest = hash_wrapper(new_status)
            new_status.pop("secret")

            print("abnormal_report:")
            print(old_status)
            data = wrap("abnormal", {"abnormal_list": abnormal_list, "old_list": old_status, "new_digest": new_digest})

            self.ssl_sock.send(data.encode("utf-8"))
            reply = int(str(self.ssl_sock.recv(1024).decode()))
            if reply == 0:
                saved_status = new_status.copy()
                break

        autils.set_hardware(str(saved_status))

        return str(reply)


def main():
    global saved_status, server_addr, server_port, saved_digest
    global interval_normal, interval_confirm
    server_addr, server_port = get_connection()
    interval_normal, interval_confirm = get_intervals()

    client = ClientSSL()

    while client.registration() == 1:
        pass

    saved_status = get_hardware()
    saved_digest = hash_wrapper(saved_status)
    client.confirmation()

    sender_thread = SenderThread(client)
    sender_thread.start()
    sender_thread.join()

    while True:
        if behavior_type == "agent":
            client = ClientSSL()
            client.registration()
            sender_thread = SenderThread(client)
            sender_thread.start()
            sender_thread.join()

        elif behavior_type == "proxy":
            proxy = ClientSSL()

            proxy_thread = ProxyThread(proxy)
            proxy_thread.start()
            proxy_thread.join()


if __name__ == "__main__":
    main()

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