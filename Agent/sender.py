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

import AUtils
import lutils
import Utilities
from AUtils import get_intervals, collect_normal, get_hardware, get_connection, hash_wrapper

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
            result = Utilities.unwrap(msg, self.thread_key)
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
