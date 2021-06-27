import random
import socket
import ssl
import threading
import time
from configparser import ConfigParser

import pymysql

import DatabaseUtils
import Utilities
import DatabaseThread
from SwitchCheckHandler import SwitchCheckHandler

web_server = ("127.0.0.1", 7776)
message_pool = []
agent_pool = dict()
proxy_raw = []
proxy_assign = dict()
agent_assigned = []



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
