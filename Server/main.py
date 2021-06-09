import random
import socket
import ssl
import threading
import time
from configparser import ConfigParser

import pymysql

import utilities
import database_ops as dbop
import DatabaseThread
from SwitchCheckHandler import SwitchCheckHandler

web_server = ("127.0.0.1", 7776)
message_pool = []
agent_pool = dict()
proxy_raw = []
proxy_assign = dict()
agent_assigned = []


class ConfigHandler(threading.Thread):

    def __init__(self):
        threading.Thread.__init__(self)

    def run(self):
        config = ConfigParser()
        config.read("C:\\Users\\Hester\\Desktop\\thesis\\th1\\Server\\config.conf")
        host = config.get("mysql", "host")
        port = config.get("mysql", "port")
        database = config.get("mysql", "database")
        username = config.get("mysql", "username")
        password = config.get("mysql", "password")
        conn = pymysql.connect(host=host, user=username, port=int(port), password=password, db=database)

        while True:
            time.sleep(20)
            cursor = conn.cursor()
            cursor.execute("select * from config_info")
            configs_info = cursor.fetchall()

            for info in configs_info:
                config = info[0]
                section = info[1]
                value = info[2]

                if int(config.get(section, config)) != value:
                    config.set(section, config, value)
                    if section == "alert":
                        pass
                    elif section == "interval":
                        message_pool.append({"type": "config_changed", "info":[{"section": "interval", "config": config, "value": value}]})
                    if config == "if_proxy" and value == 1:
                        cursor.execute("select * from proxy_list")
                        addr_list = cursor.fetchall()
                        new_addr = []
                        for addr in addr_list:
                            new_addr.append(addr[0])
                        addr_list = new_addr

                        proxy_build_signal(addr_list)
                        len_proxy_list = len(addr_list)
                        len_agent_list = len(agent_pool)-len_proxy_list
                        while True:
                            time.sleep(5)
                            if len(proxy_raw) == len_proxy_list:
                                break
                        while True:
                            flag = len_proxy_list
                            for rtt_list in proxy_raw:
                                if len(proxy_raw[rtt_list]) == len_agent_list:
                                    flag -= 1
                            if flag == 0:
                                break

                        for rtt_list in proxy_raw:
                            proxy_raw[rtt_list].sort()

                        global proxy_assign
                        proxy_assign = dict()

                        n = len_agent_list//len_proxy_list + 1
                        while len_agent_list > 0:
                            min_list = []
                            i = 0
                            for rtt_list in proxy_raw:
                                min_list.append((proxy_raw[rtt_list][0], rtt_list))
                                i += 1

                            min_rtt = min(min_list)
                            proxy_assign[min_rtt[1]].append(min_rtt[0])
                            len_agent_list -= 1
                            if len(proxy_assign[min_rtt[1]]) == n:
                                proxy_raw.pop(min_rtt[1])

                            for rtt_list in proxy_raw:
                                real_list = proxy_raw[rtt_list]
                                for item in real_list:
                                    if item[1] == min_rtt[0][1]:
                                        real_list.remove(item)

                        change_server_signal(proxy_assign)

                elif config == "if_proxy" and value == 0:
                    for addr in proxy_assign:
                        agent_pool[addr]["message"].apped(str("cancel"))

                config.write(open("C:\\Users\\Hester\\Desktop\\thesis\\th1\\Server\\config.conf", "w"))


def change_server_signal(proxy_assign):
    config = ConfigParser()
    config.read("C:\\Users\\Hester\\Desktop\\thesis\\th1\\Server\\config.conf")
    host = config.get("mysql", "host")
    port = config.get("mysql", "port")
    database = config.get("mysql", "database")
    username = config.get("mysql", "username")
    password = config.get("mysql", "password")
    conn = pymysql.connect(host=host, user=username, port=int(port), password=password, db=database)
    cursor = conn.cursor()

    key_alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890"
    key_space = len(key_alphabet)
    random.seed(time.time())
    key = ""

    # generate a ramdom key

    for proxy in proxy_assign:
        for agent in proxy_assign[proxy]:
            key = ""
            for i in range(32):
                key += key_alphabet[random.randint(0, key_space-1)]

            cursor.execute("select digest from machines where identity = %d" % int(agent_pool["agent"]["identity"]))
            digest = cursor.fetchone()[0]
            agent_pool[agent]["message"].append(str({"type": "change_server", "new_addr": proxy, "new_port": 9556, "new_key": key}))
            agent_pool[proxy]["message"].append(str({"secret": key, "digest": digest, "identity": agent_pool["agent"]["identity"]}))

    conn.close()


def proxy_build_signal(addr_list):
    agent_pool.clear()
    agent_assigned.clear()

    for addr in agent_pool:
        if addr not in addr_list:
            agent_assigned.append(addr)
    for addr in addr_list:
        agent_pool[addr]["message"].append(str({"type": "proxy"}))


class HandlerThread(threading.Thread):
    key_settled = False
    thread_key = 0

    # save ssl_socket information
    def __init__(self, client_sock, addr):
        threading.Thread.__init__(self)
        self.client_socket = client_sock
        self.client_addr = addr

    def run(self):
        print("start thread")
        global message_pool
        global agent_pool
        while True:
            msg = self.client_socket.recv(4096).decode("utf-8")
            if not msg:
                break

            # unwrap the message
            # format:
            # "type": str, "identity": int, "status": str, "info":dict
            result = utilities.unwrap(msg, self.thread_key)
            if result["status"] == "sound":
                print(f"receive msg from client {self.client_addr}：{msg}")
                if (not self.key_settled) and result["type"] == "confirmation":
                    self.thread_key = dbop.Actions().get_comm_key(result["identity"])
                    self.key_settled = True
                    agent_pool[self.client_addr[0]].update({"identity": result["identity"]})

                if result["type"] in ["registration", "confirmation", "normal", "abnormal"]:
                    new_msg = str(self.parse(result))

                    if len(agent_pool[self.client_addr[0]]["message"]) != 0:
                        msg_pool = agent_pool[self.client_addr[0]]["message"]
                        self.client_socket.send(str(msg_pool[0]).encode("utf-8"))
                        agent_pool[self.client_addr[0]]["message"] = agent_pool[self.client_addr[0]]["message"][1:]
                    elif len(message_pool) != 0:
                        self.client_socket.send(str(message_pool[0]["msg"]).encode("utf-8"))
                        message_pool[0]["ctr"] -= 1
                        if message_pool[0]["ctr"] == 0:
                            message_pool = message_pool[1:]

                    self.client_socket.send(new_msg.encode("utf-8"))
                elif result["type"] == "proxy_reg":
                    assign_agent(self.client_socket, self.client_addr[0])

            # integrity check failed
            # or timeout
            # todo: write error to the log
            else:
                print(result["status"] + ': ' + result["description"])
                self.client_socket.send(str(1).encode("utf-8"))

    def parse(self, result):
        # redirect to different functions
        method_dict = {
            "registration": dbop.Actions().registration,
            "confirmation": dbop.Actions().confirmation,
            "normal": normal_check,
            "abnormal": abnormal_check,
        }
        # print(result)
        msg_type = result["type"]
        return method_dict.get(msg_type)(result)

    # when thread is destroyed
    # close the ssl_socket
    def __del__(self):
        print("thread del called here")
        self.client_socket.close()


def assign_agent(proxy_sock, proxy_addr):
    for addr in agent_assigned:
        proxy_sock.send(str(addr).encode("utf-8"))

    proxy_sock.send("done".encode("utf-8"))

    num = len(agent_assigned)

    proxy_raw[proxy_addr] = []

    while num != 0:
        ret = proxy_sock.recv(1024).decode()
        agent_addr = ret["addr"]
        agent_rtt = ret["rtt"]

        proxy_raw[proxy_addr].append((float(agent_rtt), agent_addr))
        num -= 1


class ServerSSL:
    def build_listen(self):
        context = ssl.SSLContext(ssl.PROTOCOL_TLSv1)
        context.load_cert_chain(certfile="C:\\Users\\Hester\\Desktop\\thesis\\th1\\Server\\cert.pem",
                                keyfile="C:\\Users\\Hester\\Desktop\\thesis\\th1\\Server\\key.pem")

        # listen
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0) as sock:
            sock.bind(('127.0.0.1', 9556))
            sock.listen(5)
            with context.wrap_socket(sock, server_side=True) as ssock:
                while True:
                    # accept the client
                    client_socket, addr = ssock.accept()
                    # start a new thread to handle it

                    thread = HandlerThread(client_socket, addr)
                    agent_pool.update({addr[0]: {"thread": thread, "message": []}})
                    thread.start()


def normal_check(result):
    try:
        if result["info"]["report"] == "none":
            return 0
        else:
            return 1
    except IndexError:
        return 2


def abnormal_check(result):
    abnormal_list = result["info"]["abnormal_list"]
    old_list = result["info"]["old_list"]
    identity = result["identity"]
    del_list = []
    insert_list = []

    # check if provided old_list is authentic
    if dbop.Actions().check_digest(identity, old_list):
        # drop different changes into different categories(list)
        # change old_list based on provided abnormal list
        print("check1")

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
        calculated_digest, fetched_digest = dbop.Actions().cal_digest(identity, old_list)

        if new_digest == calculated_digest:
            dbop.Actions().abnormal_update(identity, del_list, insert_list, new_digest)
            return 0
    dbop.Actions().integrity_failed_log(identity)
    return 1


if __name__ == "__main__":
    db_thread = DatabaseThread.DatabaseThread()
    db_thread.start()
    switch_thread = SwitchCheckHandler()
    switch_thread.start()
    server = ServerSSL()
    server.build_listen()
